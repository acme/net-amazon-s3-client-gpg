#!perl
use warnings;
use strict;
use lib 'lib';
use Digest::MD5::File qw(file_md5_hex);
use GnuPG::Interface;
use LWP::Simple;
use File::stat;
use Test::More;
use Test::Exception;

unless ( $ENV{'AMAZON_S3_EXPENSIVE_TESTS'} ) {
    plan skip_all => 'Testing this module for real costs money.';
} else {
    plan tests => 17;
}

use_ok('Net::Amazon::S3');
use_ok('Net::Amazon::S3::Client::GPG');

my $aws_access_key_id     = $ENV{'AWS_ACCESS_KEY_ID'};
my $aws_secret_access_key = $ENV{'AWS_ACCESS_KEY_SECRET'};
my $gpg_recipient         = $ENV{'GPG_RECIPIENT'} || die "No recipient";
my $gpg_passphrase        = $ENV{'GPG_PASSPHRASE'} || die "No passphrase";

my $s3 = Net::Amazon::S3->new(
    aws_access_key_id     => $aws_access_key_id,
    aws_secret_access_key => $aws_secret_access_key,
    retry                 => 1,
);

my $gnupg = GnuPG::Interface->new();
$gnupg->options->hash_init(
    armor            => 0,
    recipients       => [$gpg_recipient],
    meta_interactive => 0,
    always_trust     => 1,
);

my $client = Net::Amazon::S3::Client::GPG->new(
    s3              => $s3,
    gnupg_interface => $gnupg,
    passphrase      => $gpg_passphrase,
);

my @buckets = $client->buckets;

TODO: {
    local $TODO = "These tests only work if you're leon";
    my $first_bucket = $buckets[0];
    like( $first_bucket->owner_id, qr/^46a801915a1711f/, 'have owner id' );
    is( $first_bucket->owner_display_name, '_acme_', 'have display name' );
    is( scalar @buckets, 10, 'have a bunch of buckets' );
}

my $bucket_name = 'net-amazon-s3-test2-' . lc $aws_access_key_id;

#$client->bucket(name => $bucket_name)->delete;

my $bucket = $client->create_bucket(
    name                => $bucket_name,
    acl_short           => 'public-read',
    location_constraint => 'US',
);

is( $bucket->name, $bucket_name, 'newly created bucket has correct name' );

like(
    $bucket->acl,
    qr{<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>[a-z0-9]{64}</ID><DisplayName>.+?</DisplayName></Owner><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>[a-z0-9]{64}</ID><DisplayName>.+?</DisplayName></Grantee><Permission>FULL_CONTROL</Permission></Grant><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>},
    'newly created bucket is public-readable'
);

is( $bucket->location_constraint, 'US', 'newly created bucket is in the US' );

my $stream = $bucket->list;
until ( $stream->is_done ) {
    foreach my $object ( $stream->items ) {
        $object->delete;
    }
}

my $count = 0;
$stream = $bucket->list;
until ( $stream->is_done ) {
    foreach my $object ( $stream->items ) {
        $count++;
    }
}

is( $count, 0, 'newly created bucket has no objects' );

my $object = $bucket->object( key => 'this is the key' );
$object->gpg_put('this is the value');

my @objects;

@objects = ();
$stream = $bucket->list( { prefix => 'this is the key' } );
until ( $stream->is_done ) {
    foreach my $object ( $stream->items ) {
        push @objects, $object;
    }
}
is( @objects, 1, 'bucket list with prefix finds key' );

@objects = ();
$stream = $bucket->list( { prefix => 'this is not the key' } );
until ( $stream->is_done ) {
    foreach my $object ( $stream->items ) {
        push @objects, $object;
    }
}
is( @objects, 0, 'bucket list with different prefix does not find key' );

@objects = ();
$stream  = $bucket->list;
until ( $stream->is_done ) {
    foreach my $object ( $stream->items ) {
        push @objects, $object;
    }
}
is( @objects, 1, 'bucket list finds newly created key' );

is( $objects[0]->key,
    'this is the key',
    'newly created object has the right key'
);

is( $object->gpg_get,
    'this is the value',
    'newly created object has the right value'
);

isnt(
    $object->get,
    'this is the value',
    'newly created object is not plaintext'
);

is( $bucket->object( key => 'this is the key' )->gpg_get,
    'this is the value',
    'newly created object fetched by name has the right value'
);

is( get( $object->uri ),
    undef, 'newly created object cannot be fetched by uri' );

$object->delete;

$bucket->delete;

