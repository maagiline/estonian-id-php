<?php

namespace maagiline\EstonianIdPhp;

use phpseclib\File\X509;
use maagiline\EstonianIdPhp\EIDOCSP;

class EidAuth
{
    public function __construct()
    {
    }

    /**
     * @param string $certificate
     * @return array
     *
     */
    public function getEIDAuth(string $certificate): array
    {
        $x509 = new X509();
        $x509->loadX509($certificate);
        $checkCert = EIDOCSP::doOCSPCheck($certificate);
        if ($checkCert["status"]) {
            $return = array();
            $return['status'] = $checkCert["status"];
            $return['statusMsg'] = $checkCert["statusMsg"];
            $return["firstName"] = $x509->getDNProp('givenName')[0];
            $return["lastName"] = $x509->getDNProp('surname')[0];
            $return["socialSecurityNumber"] = $x509->getDNProp('serialNumber')[0];
            return $return;
        }
        return [
            'status' => $checkCert["status"],
            'errorMsg' => $checkCert["statusMsg"],
        ];
    }
}
