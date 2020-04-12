# golang openpgp example
This project show how to use golang openpgp  library encrypt/decrypt PGP message.
we use a public key to encrypt and private key to sign a message.

## 1. First, something about PGP
Something you should know about PGP before started.
* [OpenPGP Message Format RFC](https://tools.ietf.org/html/rfc4880)
* [GNUPG Handbook](https://www.gnupg.org/gph/en/manual.html)


### Common used command about gpg
```
1. list local public key
    gpg --list-keys 

2.export 
 gpg --output example.gpg --export example@abc.org
   
3.export  armor KEY
  gpg --armor --export example@abc.org

```

### PGP encrypt/decrypt Message
```
 1.encrpyt & sign & compress message
 gpg    --encrypt --sign --armor  --cipher-algo AES256 --digest-algo SHA256  --compress-algo 1 -r {Recipient} -u {uid}     {need_to_be_encypt}

 2.decrypt
 gpg --output {out_file} --decrypt  {need_be_decrypt}
```


## 2. golang PGP
* [golang openpgp](https://godoc.org/golang.org/x/crypto/openpgp)
* [example-1](https://github.com/joncrlsn/go-examples/blob/master/gpg.go)


### how to prepare key for openPGP
* [first step](https://superuser.com/questions/399938/how-to-create-additional-gpg-keyring),
* [second](https://gist.github.com/stuart-warren/93750a142d3de4e8fdd2),command below:
```
first:
    transfer PGP key to  keyring 
    gpg --keyring pubring.gpg --export KEY > /tmp/exported.key
    gpg --no-default-keyring --/=path/to/new-keyring.gpg --import /tmp/exported.key

second:
    gnupg>v2 for golang
    gpg --no-default-keyring --keyring ./ring.gpg --export-secret-keys > secret-key.gpg
```

## 3. PHP-FFI use golang PGP
PHP7.4 supports FFI feature,allow us to use shared c library in PHP.
see [LIB FFI](https://github.com/libffi/libffi),how to install [PHP-FFI](https://github.com/dstogov/php-ffi)
```
 php-ffi depends libffi
  yum -y libffi libffi-devel OR apt-get install libffi6 libffi-dev

  if your PHP version >=7.4, you should use PHP source code ext to install php-ffi
```

### use go IN PHP
[a simple example](https://github.com/eislambey/php-ffi-go-example), [variable define](https://golang.org/cmd/cgo/#hdr-Go_references_to_C)


## 4. More referrence
[openPGP for developer](https://www.openpgp.org/software/developer/)