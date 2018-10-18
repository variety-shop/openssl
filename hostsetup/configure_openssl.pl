package configure_openssl;

use strict;
use akamailog;
use File::Basename;
use config qw( $global_conf_data );

my $varname = "openssl_executable";
my $thiscomponent = "openssl";

sub special {
    my ($installed_root, $temp_root, $request) = @_;
    # Run ldconfig to pick up /etc/ld.conf.so.d/akamai-openssl.conf
    system("/sbin/ldconfig");
    1;
}

sub install_openssl_here {
    1;
}

sub register {
    1;
}

sub usereg {
    mh1::findordie("api-bundler-1.0")->installbundle( sub { install_openssl_here(@_) }, type=>["software"], component=>["openssl"]);
    1;
}

sub configure {
    my ($tmp_root, $host) = @_;
    my $akamai = &config::akamai_dir();
    my $bin = "$tmp_root/$akamai/bin";
    my $hostobj = $config::global_conf_data->return_host($host);
    my $variance = $config::global_conf_data->get_host_variance($hostobj, $varname);

    if (-f "$bin/openssl") {
        akamai_die(AKALOG_ERROR, 0, "$host:$thiscomponent: openssl exectuable already exists");
    }

    if (defined $variance) {
        if ($variance !~ m/openssl[1-9][0-9][0-9]/) {
            akamai_die(AKALOG_ERROR, 0, "$host:$thiscomponent: '$varname' variance '$variance', inalid value");
        }
        if (! -f "$bin/$variance") {
            akamai_die(AKALOG_ERROR, 0, "$host:$thiscomponent: '$varname' variance '$variance', file not found");
        }

        akamai_log(AKALOG_INFO, 0, "$host:$thiscomponent: '$varname' variance '$variance', creating link");

    } else {
        # variance is undefined, check for an openssl executable
        my @files = glob("$bin/openssl[1-9][0-9][0-9]*");

        $variance = shift(@files);

        if (! defined $variance) {
            akamai_die(AKALOG_ERROR, 0, "$host:$thiscomponent: '$varname' variance does not exist, cannot find exectuable");
        }

        # strip the path name so we can use it below
        $variance = basename($variance);

        akamai_log(AKALOG_INFO, 0, "$host:$thiscomponent: '$varname' variance does not exist, creating link to '$variance'");
    }

    main::log_symlink("./$variance", "$bin/$thiscomponent");
    1;
}

1;
