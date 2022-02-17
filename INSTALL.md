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
$ sudo apt install nsis
```

#### Build

```
$ ./configure --host=x86-w64-mingw32 --prefix=/ ...
$ make install DESTDIR="$(pwd)/tmp"
$ DESTDIR=tmp ./packaging/windows-nsis/build
```
