# mycms Installation

POSIX and Windows (using mingw-w64) are supported.

## Dependencies

### Standard Dependencies

* `pkg-config` complaint
* `>=openssl-1.1`

### Test Dependencies

* softhsm2
* easy-rsa
* awk compliant
* Optional
  * `valgrind`

### Checkout Dependencies

* autoconf
* automake
* libtool

Run:

```
$ autoreconf -ivf
```

## Development

Use `conf-dev.sh` to configure all features during development.

Use `MYCMS_DO_VALGRIND=1 make check` to check using `valgrind`.

## Packaging

### Debian

#### Dependencies

##### Prepare

```
$ ln -s packaging/debian
```

##### Install

```
$ sudo apt install build-essential devscripts equivs
$ sudo mk-build-deps -i
```

##### Remove

```
$ sudo apt remove mycms-build-deps
```

#### Build

```
$ debuild -b -uc -us -i
```

#### Release

Due to `deb` magics, before release version must be updated manually in `packaging/debian/changelog`.

#### Install Manually

```
$ dpkg -i mycms*.deb
```

### Windows NSIS

#### Dependencies

```
$ sudo apt install mingw-w64 nsis
```

#### Build

```
$ MYCMS_PREFIX=/tmp/mycms-prefix
```

#### OpenSSL Build

Download and extract OpenSSL tarball.

Run the following in OpenSSL source directory:

```
$ ./Configure --prefix="${MYCMS_PREFIX}" --cross-compile-prefix=x86_64-w64-mingw32- mingw64
$ make install_dev

```

#### mycms Build

```
$ ./configure --host=x86_64-w64-mingw32 --prefix="${MYCMS_PREFIX}" \
    --enable-tool \
    --enable-io-driver-file \
    @ANY_ADDITIONAL_CONFIG@ \
    PKG_CONFIG_PATH="${MYCMS_PREFIX}/lib64/pkgconfig/"
$ make install
$ DESTDIR="${MYCMS_PREFIX}" ./packaging/windows-nsis/build
```
