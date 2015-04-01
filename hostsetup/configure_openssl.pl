
package configure_openssl;

use strict;
use akamailog;
use config qw( $global_conf_data );

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

1;

