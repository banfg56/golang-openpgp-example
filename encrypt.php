<?php
/**
 * PHP-go 加密签名测试
 * 
 */

$secretKeyFile =  dirname(__FILE__).'/path-to-key/secret-key.gpg';
$secretPass = 'xxxxx';
$pubKeyFile = dirname(__FILE__).'/path-to-key/public-key.gpg';
$dbsPublicFile = dirname(__FILE__).'/path-to-key/public.gpg';
 

$appPath = realpath(dirname(__FILE__)).'/';
echo "Start  ",date('Y-m-d H:i:s'),"\n";


$dtl = \FFI::cdef(
    " 
        char* enCryptSign(char* p1,char* p2,char* p3,char* p4);  
        char* deCrypt(char* p1,char* p2,char* p3,char* p4);
        
    ",
    $appPath."go-php/lib.so",
    );
        
    
$ffiCData  = $dtl->enCryptSign($content2Encrypt, $pubKeyFile, $secretKeyFile, $secretPass);
$res = \FFI::string($ffiCData);
\FFI::free($ffiCData);
$jRet = json_decode($res, TRUE);
var_dump( $jRet );


// echo "Decrypt PGP Message\n";
// $ffiCData  = $dtl->deCrypt($contentNeed2Decrypted, $pubKeyFile, $secretKeyFile, $secretPass);
// $res = \FFI::string($ffiCData);
// \FFI::free($ffiCData);
// $jRet = json_decode($res, TRUE);
// var_dump( $jRet );

?>