package Net::Amazon::S3::Client::GPG;
use Moose;
use MooseX::StrictConstructor;
use Moose::Util::TypeConstraints;
use Digest::MD5 qw(md5 md5_hex);
use MIME::Base64;
use Net::Amazon::S3;
use Net::Amazon::S3::Client;
use Net::Amazon::S3::Client::Object;
extends 'Net::Amazon::S3::Client';

has 'passphrase' => ( is => 'ro', isa => 'Str', required => 0 );
has 'gnupg_interface' =>
    ( is => 'ro', isa => 'GnuPG::Interface', required => 1 );

__PACKAGE__->meta->make_immutable;

Net::Amazon::S3::Client::Object->meta->make_mutable();
Net::Amazon::S3::Client::Object->meta->add_method(
    'gpg_get' => sub {
        my $self = shift;
        my $client = $self->client;
        
        my $http_request = Net::Amazon::S3::Request::GetObject->new(
            s3     => $self->client->s3,
            bucket => $self->bucket->name,
            key    => $self->key,
            method => 'GET',
        )->http_request;

        my $http_response = $client->_send_request($http_request);
        my $content       = $http_response->content;

        my $md5_hex = md5_hex($content);

        if ( $self->etag ) {
            confess 'Corrupted download' if $self->etag ne $md5_hex;
        } else {
            confess 'Corrupted download'
                if $self->_etag($http_response) ne $md5_hex;
        }
        my $plaintext = $client->decrypt($content);
        return $plaintext;
    }
);
Net::Amazon::S3::Client::Object->meta->add_method(
    'gpg_put' => sub {
        my ( $self, $value ) = @_;
        my $client = $self->client;

        my $ciphertext = $client->encrypt($value);

        my $md5        = md5($ciphertext);
        my $md5_hex    = unpack( 'H*', $md5 );
        my $md5_base64 = encode_base64($md5);
        chomp $md5_base64;
        
        my $conf = {
            'Content-MD5'    => $md5_base64,
            'Content-Length' => length $ciphertext,
            'Content-Type'   => $self->content_type,
        };

        if ( $self->expires ) {
            $conf->{Expires}
                = DateTime::Format::HTTP->format_datetime( $self->expires );
        }

        my $http_request = Net::Amazon::S3::Request::PutObject->new(
            s3        => $self->client->s3,
            bucket    => $self->bucket->name,
            key       => $self->key,
            value     => $ciphertext,
            headers   => $conf,
            acl_short => $self->acl_short,
        )->http_request;

        my $http_response = $self->client->_send_request($http_request);

        confess 'Error uploading' if $http_response->code != 200;

        my $etag = $self->_etag($http_response);

        confess 'Corrupted upload' if $etag ne $md5_hex;
    }
);
Net::Amazon::S3::Client::Object->meta->make_immutable();

sub encrypt {
    my ( $self, $plaintext ) = @_;
    my $gnupg = $self->gnupg_interface;

    my $input   = IO::Handle->new();
    my $output  = IO::Handle->new();
    my $handles = GnuPG::Handles->new(
        stdin  => $input,
        stdout => $output,
    );
    my $pid = $gnupg->encrypt( handles => $handles );

    print $input $plaintext;
    close $input;

    my $ciphertext = join '', <$output>;
    close $output;

    waitpid $pid, 0;
    return $ciphertext;
}

sub decrypt {
    my ( $self, $ciphertext ) = @_;
    my $gnupg = $self->gnupg_interface;

    # This time we'll catch the standard error for our perusing
    # as well as passing in the passphrase manually
    # as well as the status information given by GnuPG
    my ( $input, $output, $error, $passphrase_fh, $status_fh ) = (
        IO::Handle->new(), IO::Handle->new(),
        IO::Handle->new(), IO::Handle->new(),
        IO::Handle->new(),
    );

    my $handles = GnuPG::Handles->new(
        stdin      => $input,
        stdout     => $output,
        stderr     => $error,
        passphrase => $passphrase_fh,
        status     => $status_fh,
    );

    # this time we'll also demonstrate decrypting
    # a file written to disk
    # Make sure you "use IO::File" if you use this module!
    #  my $cipher_file = IO::File->new( 'encrypted.gpg' );

    # this sets up the communication
    my $pid = $gnupg->decrypt( handles => $handles );

    # This passes in the passphrase
    print $passphrase_fh $self->passphrase;
    close $passphrase_fh;

    # this passes in the plaintext
    #  print $input $_ while <$cipher_file>;
    print $input $ciphertext;

    # this closes the communication channel,
    # indicating we are done
    close $input;

    #  close $cipher_file;

    my $plaintext    = join '', <$output>;       # reading the output
    my $error_output = join '', <$error>;        # reading the error
    my $status_info  = join '', <$status_fh>;    # read the status info

    # clean up...
    close $output;
    close $error;
    close $status_fh;

    #warn $error_output;
    #warn $status_info;

    waitpid $pid, 0;    # clean up the finished GnuPG process
    return $plaintext;
}

1;
