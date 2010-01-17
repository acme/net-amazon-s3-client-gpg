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
        my $self       = shift;
        my $ciphertext = $self->get;
        return $self->client->decrypt($ciphertext);
    }
);
Net::Amazon::S3::Client::Object->meta->add_method(
    'gpg_put' => sub {
        my ( $self, $value ) = @_;
        my $ciphertext = $self->client->encrypt($value);
        return $self->put($ciphertext);
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
