#!/bin/bash
#tgtdir=/Users/`whoami`/nginx
tgtdir=/usr/local/nginx
flags="--with-debug --with-stream --with-http_ssl_module --with-http_slice_module --with-stream_ssl_module --with-http_stub_status_module --add-module=./modules/nginx-http-active-probe-module --with-cc=/usr/bin/cc --with-cc-opt=-O0  --prefix=$tgtdir"
module_flags="--with-compat --add-dynamic-module=./modules/nginx-http-active-probe-module"
cdir=`cd $(dirname $0); pwd`
(
    cd $cdir
    set -e
    for option; do
        case $option in
            conf*)
                ./configure $flags
                ;;
            make)
                make
                ;;
            install)
                make install
                ;;
            clean)
                make clean
                ;;
            release)
                if [ -f ./objs/nginx ]; then
                    make clean
                fi
                ./configure $flags
                 make;
                cp objs/nginx objs/nginx.debug
                objcopy --strip-unneeded ./objs/nginx
                ;;
            modules)
                if [ -f ./objs/nginx ]; then
                    make clean
                fi
                ./configure $module_flags
                 make modules;
                 ;;
            *)
                echo "$0 [conf[igure]|make|install|clean|release]"
                ;;
        esac
    done
    set +e
)
