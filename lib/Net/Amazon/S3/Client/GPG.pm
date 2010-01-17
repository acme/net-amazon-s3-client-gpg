package Net::Amazon::S3::Client::GPG;
use Moose;
use MooseX::StrictConstructor;
use Moose::Util::TypeConstraints;
use Carp qw(confess);
use Digest::MD5 qw(md5 md5_hex);
use File::Temp qw(tempfile);
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
        my ( $ciphertext_fh, $ciphertext_filename ) = tempfile();
        $ciphertext_fh->close || confess "Error closing filehandle: $!";
        $self->get_filename($ciphertext_filename);

        my ( $tmp_plaintext_fh, $plaintext_filename ) = tempfile();
        $tmp_plaintext_fh->close;

        $self->client->decrypt( $ciphertext_filename, $plaintext_filename );

        unlink($ciphertext_filename)
            || confess "Error unlinking $ciphertext_filename: $!";

        my $plaintext_fh = IO::File->new($plaintext_filename)
            || confess "Error opening $plaintext_filename: $!";
        my $plaintext;
        until ( $plaintext_fh->eof ) {
            $plaintext_fh->read( my $chunk, 4096 )
                || confess "Error reading from plaintext: $!";
            $plaintext .= $chunk;
        }
        $plaintext_fh->close;

        unlink($plaintext_filename)
            || confess "Error unlinking $plaintext_filename: $!";
        return $plaintext;
    }
);
Net::Amazon::S3::Client::Object->meta->add_method(
    'gpg_put' => sub {
        my ( $self,         $plaintext )          = @_;
        my ( $plaintext_fh, $plaintext_filename ) = tempfile();
        $plaintext_fh->print($plaintext)
            || confess "Error printing the value: $!";
        $plaintext_fh->close || confess "Error closing filehandle: $!";

        my $ciphertext_filename = $self->client->encrypt($plaintext_filename);
        $self->put_filename($ciphertext_filename);

        unlink($plaintext_filename)
            || confess "Error unlinking $plaintext_filename: $!";
        unlink($ciphertext_filename)
            || confess "Error unlinking $ciphertext_filename: $!";
    }
);
Net::Amazon::S3::Client::Object->meta->make_immutable();

sub decrypt {
    my ( $self, $ciphertext_filename, $plaintext_filename ) = @_;
    my $gnupg = $self->gnupg_interface;

    my $ciphertext_fh = IO::File->new($ciphertext_filename)
        || confess "Error opening $ciphertext_filename: $!";

    my $plaintext_fh = IO::File->new( $plaintext_filename, 'w' )
        || confess "Error opening $plaintext_filename: $!";

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

    # this sets up the communication
    my $pid = $gnupg->decrypt( handles => $handles )
        || confess "Error decrypting: no pid!";

    # This passes in the passphrase
    $passphrase_fh->print( $self->passphrase )
        || confess "Error printing passphrase: $!";
    $passphrase_fh->close || confess "Error closing passphrase: $!";

    until ( $ciphertext_fh->eof ) {
        $ciphertext_fh->read( my $chunk, 4096 )
            || confess "Error reading from ciphertext: $!";
        $input->print($chunk) || confess "Error printing the ciphertext: $!";
    }

    $input->close         || confess "Error closing input: $!";
    $ciphertext_fh->close || confess "Error closing ciphertext: $!";

    until ( $output->eof ) {
        $output->read( my $chunk, 4096 )
            || confess "Error reading from output: $!";
        $plaintext_fh->print($chunk)
            || confess "Error writing the plaintext: $!";
    }
    $output->close       || confess "Error closing output: $!";
    $plaintext_fh->close || confess "Error closing plaintext: $!";

    my $error_output = join '', <$error>;        # reading the error
    my $status_info  = join '', <$status_fh>;    # read the status info

    # clean up...
    $error->close     || confess "Error closing error: $!";
    $status_fh->close || confess "Error closing status: $!";

    #warn $error_output;
    #warn $status_info;

    waitpid $pid, 0;    # clean up the finished GnuPG process
}

sub encrypt {
    my ( $self, $plaintext_filename ) = @_;
    my $gnupg = $self->gnupg_interface;

    my $plaintext_fh = IO::File->new($plaintext_filename)
        || confess "Error opening $plaintext_filename: $!";
    my ( $ciphertext_fh, $ciphertext_filename ) = tempfile();

    my $input   = IO::Handle->new();
    my $output  = IO::Handle->new();
    my $handles = GnuPG::Handles->new(
        stdin  => $input,
        stdout => $output,
    );
    my $pid = $gnupg->encrypt( handles => $handles )
        || confess "Error encrypting: no pid!";

    until ( $plaintext_fh->eof ) {
        $plaintext_fh->read( my $chunk, 4096 )
            || confess "Error reading from plaintext: $!";
        $input->print($chunk) || confess "Error printing the plaintext: $!";
    }

    $input->close || confess "Error closing filehandle: $!";

    until ( $output->eof ) {
        $output->read( my $chunk, 4096 )
            || confess "Error reading from output: $!";
        $ciphertext_fh->print($chunk)
            || confess "Error writing the ciphertext: $!";
    }
    $output->close || confess "Error closing filehandle: $!";

    waitpid $pid, 0;
    return $ciphertext_filename;
}

1;
