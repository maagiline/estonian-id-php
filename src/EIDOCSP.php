<?php

namespace maagiline\EstonianIdPhp;

use phpseclib\File\X509;

// Source: https://www.id.ee/index.php?id=30338

class EIDOCSP
{
    public function __construct()
    {
    }

    /**
     * @param string $pemCert
     * @return array
     * Different statuses definitions:
    0 - OCSP certificate status unknown
    1 - OCSP certificate status good / valid
    2 - OCSP internal error
    3 - OCSP certificate status revoked
    4 - Some error in script
     */
    public static function doOCSPCheck(string $pemCert): array
    {
        $status_options = [
            0 => "OCSP certificate status unknown",
            1 => "OCSP certificate status good / valid",
            2 => "OCSP internal error",
            3 => "OCSP certificate status revoked",
            4 => "Some error in script",
        ];

        // User certificate issuer certificate file location
        $ocsp_info = array();
        // EE-GovCA2018
        $ocsp_info["EE-GovCA2018"]["CA_CERT_FILE"] = resource_path("EIDCerts/EE-GovCA2018.crl");
        $ocsp_info["EE-GovCA2018"]["OCSP_SERVER_URL"] = 'http://ocsp.sk.ee';
        $ocsp_info["EE-GovCA2018"]["OCSP_SERVER_CERT_FILE"] = resource_path("EIDCerts/SK_OCSP_RESPONDER_2011.pem.cer");

        // ESTEID2018
        $ocsp_info["EE-GovCA2018"]["CA_CERT_FILE"] = resource_path("EIDCerts/esteid2018.crl");
        $ocsp_info["EE-GovCA2018"]["OCSP_SERVER_URL"] = 'http://ocsp.sk.ee';
        $ocsp_info["EE-GovCA2018"]["OCSP_SERVER_CERT_FILE"] = resource_path("EIDCerts/SK_OCSP_RESPONDER_2011.pem.cer");
        // EE Certification Centre Root CA
        $ocsp_info["EE Certification Centre Root CA"]["CA_CERT_FILE"] = resource_path("EIDCerts/eeccrca.crl");
        $ocsp_info["EE Certification Centre Root CA"]["OCSP_SERVER_URL"] = 'http://ocsp.sk.ee';
        $ocsp_info["EE Certification Centre Root CA"]["OCSP_SERVER_CERT_FILE"] =
            resource_path("EIDCerts/SK_OCSP_RESPONDER_2011.pem.cer");

        // EID-SK 2011
        $ocsp_info["EID-SK 2011"]["CA_CERT_FILE"] = resource_path("EIDCerts/EID-SK_2011.crt");
        $ocsp_info["EID-SK 2011"]["OCSP_SERVER_URL"] = 'http://ocsp.sk.ee';
        $ocsp_info["EID-SK 2011"]["OCSP_SERVER_CERT_FILE"] = resource_path("EIDCerts/SK_OCSP_RESPONDER_2011.pem.cer");


        // Checking status of certificates issued from "ESTEID-SK 2011" against live OCSP
        // ESTEID-SK 2011 - CA for Estonian national ID-card certificates issued since 2011
        $ocsp_info["ESTEID-SK 2011"]["CA_CERT_FILE"] = resource_path("EIDCerts/ESTEID-SK_2011.crt");
        $ocsp_info["ESTEID-SK 2011"]["OCSP_SERVER_URL"] = 'http://ocsp.sk.ee';
        $ocsp_info["ESTEID-SK 2011"]["OCSP_SERVER_CERT_FILE"] =
            resource_path("EIDCerts/SK_OCSP_RESPONDER_2011.pem.cer");


        // Checking status of certificates issued from "ESTEID-SK 2015" against live OCSP
        // ESTEID-SK 2015
        $ocsp_info["ESTEID-SK 2015"]["CA_CERT_FILE"] = resource_path("EIDCerts/ESTEID-SK_2015.pem.crt");
        $ocsp_info["ESTEID-SK 2015"]["OCSP_SERVER_URL"] = 'http://ocsp.sk.ee';
        $ocsp_info["ESTEID-SK 2015"]["OCSP_SERVER_CERT_FILE"] =
            resource_path("EIDCerts/SK_OCSP_RESPONDER_2011.pem.cer");


        // KLASS3-SK 2010 - CA for company certificates KLASS3-SK 2010 (EECCRCA, SHA384)
        $ocsp_info["KLASS3-SK 2010"]["CA_CERT_FILE"] = resource_path("EIDCerts/KLASS3-SK_2010_EECCRCA_SHA384.pem.crt");
        $ocsp_info["KLASS3-SK 2010"]["OCSP_SERVER_URL"] = 'http://ocsp.sk.ee';
        $ocsp_info["KLASS3-SK 2010"]["OCSP_SERVER_CERT_FILE"] =
            resource_path("EIDCerts/SK_OCSP_RESPONDER_2011.pem.cer");

        $ocsp_info["OPEN_SSL_BIN"] = config('eid.openssl_bin');
        // Saving user certificate file to OCSP temp folder
        $ocsp_info["OCSP_TEMP_DIR"] = config('eid.tmp_dir');

        $tmp_f = fopen($tmp_f_name = tempnam($ocsp_info["OCSP_TEMP_DIR"], 'ocsp_check'), 'w');
        fwrite($tmp_f, $pemCert);
        fclose($tmp_f);

        $x509cert = new X509();
        $x509cert->loadX509($pemCert);
        $issuer_dn = $x509cert->getChain()[0]['tbsCertificate']['issuer']['rdnSequence'][3][0]['value']['utf8String'];

        $ca_cert = $ocsp_info[$issuer_dn]["CA_CERT_FILE"];
        $ocsp_server_cert = $ocsp_info[$issuer_dn]["OCSP_SERVER_CERT_FILE"];
        $ocsp_server_url = $ocsp_info[$issuer_dn]["OCSP_SERVER_URL"];

        $errorstr = "";
        $oscp_status = 4;

        if (isset($ca_cert) && isset($ocsp_server_cert) && isset($ocsp_server_url)) {
            // Making OCSP request using OpenSSL ocsp command
            $command = $ocsp_info["OPEN_SSL_BIN"] . ' ocsp -issuer ' . $ca_cert . ' -cert ';
            $command .= $tmp_f_name . ' -url ' . $ocsp_server_url . ' -VAfile ' . $ocsp_server_cert;

            $descriptorspec = array(
                0 => array("pipe", "r"),  // stdin i
                //s a pipe that the child will read from
                1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
                2 => array("pipe", "w") // stderr is a pipe that the child will write to
            );

            $process = proc_open($command, $descriptorspec, $pipes);

            if (is_resource($process)) {
                fclose($pipes[0]);

                // Getting errors from stderr
                while ($line = fgets($pipes[2])) {
                    $errorstr .= $line;
                }

                if ($errorstr !== "" && (strpos($errorstr, "Response verify OK") !== 0)) {
                    $oscp_status = 4;
                } else {
                    // Parsing OpenSSL command stdout
                    while ($line = fgets($pipes[1])) {
                        if (strstr($line, 'good')) {
                            $oscp_status = 1;
                        } elseif (strstr($line, 'internalerror (2)')) {
                            $oscp_status = 2;
                        } elseif (strstr($line, 'revoked')) {
                            $oscp_status = 3;
                        }
                    }
                    fclose($pipes[1]);
                }

                proc_close($process);
            }
        }
        $return = array();
        $return["statusMsg"] = $status_options[$oscp_status];
        if (strlen($errorstr) > 0) {
            $return["statusMsg"] .= ': ' . $errorstr;
        }
        if ($oscp_status === 1) {
            $return["status"] = true;
        } else {
            $return["status"] = false;
        }
        return $return;
    }
}
