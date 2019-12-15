<?php

namespace maagiline\EstonianIdPhp;

use Sk\Mid\DisplayTextFormat;
use Sk\Mid\Exception\DeliveryException;
use Sk\Mid\Exception\InvalidNationalIdentityNumberException;
use Sk\Mid\Exception\InvalidPhoneNumberException;
use Sk\Mid\Exception\InvalidUserConfigurationException;
use Sk\Mid\Exception\MidInternalErrorException;
use Sk\Mid\Exception\MidSessionNotFoundException;
use Sk\Mid\Exception\MidSessionTimeoutException;
use Sk\Mid\Exception\MissingOrInvalidParameterException;
use Sk\Mid\Exception\NotMidClientException;
use Sk\Mid\Exception\PhoneNotAvailableException;
use Sk\Mid\Exception\UnauthorizedException;
use Sk\Mid\Exception\UserCancellationException;
use Sk\Mid\Language\ENG;
use Sk\Mid\MobileIdAuthenticationHashToSign;
use Sk\Mid\MobileIdClient;
use Sk\Mid\Rest\Dao\Request\AuthenticationRequest;
use Sk\Mid\Util\MidInputUtil;

class MIDAuth
{
    public function __construct()
    {
    }

    /**
     * @param mixed[] $input
     * @return array
     *
     */
    public static function initiateMIDAuth(array $input): array
    {
        try {
            $phoneNumber = MidInputUtil::getValidatedPhoneNumber($input['phone']);
            $nationalIdentityNumber = MidInputUtil::getValidatedNationalIdentityNumber($input['ssn']);
        } catch (InvalidPhoneNumberException $e) {
            $return['status'] = false;
            $return['message'] = 'The phone number you entered is invalid';
            return $return;
        } catch (InvalidNationalIdentityNumberException $e) {
            $return['status'] = false;
            $return['message'] = 'The national identity number you entered is invalid';
            return $return;
        }
        // create client with long-polling
        $client = MobileIdClient::newBuilder()
            ->withRelyingPartyUUID(config('eid.mid_service_uuid'))
            ->withRelyingPartyName(config('eid.mid_service_name'))
            ->withHostUrl(config('eid.mid_service_url'))
            ->withLongPollingTimeoutSeconds(60)
            ->withPollingSleepTimeoutSeconds(2)
            ->build();


        // generate hash & calculate verification code and display to user

        $authenticationHash = MobileIdAuthenticationHashToSign::generateRandomHashOfDefaultType();
        $verificationCode = $authenticationHash->calculateVerificationCode();

        // create request to be sent to user's phone

        $request = AuthenticationRequest::newBuilder()
            ->withPhoneNumber($phoneNumber)
            ->withNationalIdentityNumber($nationalIdentityNumber)
            ->withHashToSign($authenticationHash)
            ->withLanguage(ENG::asType())
            ->withDisplayText(config('eid.mid_auth_message'))
            ->withDisplayTextFormat(DisplayTextFormat::GSM7)
            ->build();

        // send request to user's phone and catch possible errors

        try {
            $response = $client->getMobileIdConnector()->initAuthentication($request);
        } catch (NotMidClientException $e) {
            $return['status'] = false;
            $return['message'] = 'You are not a Mobile-ID client or your Mobile-ID certificates are revoked.';
            return $return;
        } catch (UnauthorizedException $e) {
            $return['status'] = false;
            $return['message'] = 'Integration error with Mobile-ID. Invalid MID credentials';
            return $return;
        } catch (MissingOrInvalidParameterException $e) {
            $return['status'] = false;
            $return['message'] = 'The national identity number you entered is invalid';
            return $return;
        } catch (MidInternalErrorException $e) {
            $return['status'] = false;
            $return['message'] = 'MID internal error';
            return $return;
        }


        // display $verificationCode (4 digit code) to user
        $return = [];
        $return['challengeId'] = $verificationCode;
        $sessCode = $response->getSessionID();
        $return['status'] = true;
        $return['EidMidClient'] = $client;
        $return['MIDAuthHash'] = $authenticationHash;
        $return['MIDSessCode'] = $sessCode;

        return $return;
    }

    /**
     * @param string $sessCode
     * @param MobileIdAuthenticationHashToSign $authHash
     * @param MobileIdClient $eidMidClient
     * @return array
     *
     */
    public static function checkMIDAuth(
        string $sessCode,
        MobileIdAuthenticationHashToSign $authHash,
        MobileIdClient $eidMidClient
    ): array {
        if (!$sessCode || $sessCode === null) {
            $return['status'] = false;
            $return['message'] = "Sessiooni viga";
            return $return;
        }
        // step #7 - keep polling for session status until we have a final status from phone
        ;
        try {
            $finalSessionStatus = $eidMidClient->getSessionStatusPoller()->fetchFinalSessionStatus($sessCode);
        } catch (UserCancellationException $e) {
            $return['status'] = false;
            $return['message'] = "You cancelled operation from your phone.";
            return $return;
        } catch (MidSessionTimeoutException $e) {
            $return['status'] = false;
            $return['message'] = "You didn't type in PIN code into your phone or there was a communication error.";
            return $return;
        } catch (PhoneNotAvailableException $e) {
            $return['status'] = false;
            $return['message'] = "Unable to reach your phone. Please make sure your phone has mobile coverage.";
            return $return;
        } catch (DeliveryException $e) {
            $return['status'] = false;
            $return['message'] = "Communication error. Unable to reach your phone.";
            return $return;
        } catch (InvalidUserConfigurationException $e) {
            $return['status'] = false;
            $return['message'] = "MID configuration on SIM card differs from what's configured on provider's side.";
            return $return;
        } catch (MidSessionNotFoundException | MissingOrInvalidParameterException | UnauthorizedException $e) {
            $return['status'] = false;
            $return['message'] = "Client side error with mobile-ID integration. Error code:" . $e->getCode();
            return $return;
        } catch (NotMidClientException $e) {
            // if user is not MID client then this exception is thrown and caught already during first request
            $return['status'] = false;
            $return['message'] = "You are not a Mobile-ID client or your Mobile-ID certificates are revoked.";
            return $return;
        } catch (MidInternalErrorException $internalError) {
            $return['status'] = false;
            $return['message'] = "Something went wrong with Mobile-ID service";
            return $return;
        }


        // step #8 - parse authenticated person out of the response and get it validated

        try {
            $authenticatedPerson = $eidMidClient
                ->createMobileIdAuthentication($finalSessionStatus, $authHash)
                ->getValidatedAuthenticationResult()
                ->getAuthenticationIdentity();
        } catch (UserCancellationException $e) {
            $return['status'] = false;
            $return['message'] = "You cancelled operation from your phone.";
            return $return;
        } catch (MidSessionTimeoutException $e) {
            $return['status'] = false;
            $return['message'] = "You didn't type in PIN code into your phone or there was a communication error.";
            return $return;
        } catch (PhoneNotAvailableException $e) {
            $return['status'] = false;
            $return['message'] = "Unable to reach your phone. Please make sure your phone has mobile coverage.";
            return $return;
        } catch (DeliveryException $e) {
            $return['status'] = false;
            $return['message'] = "Communication error. Unable to reach your phone.";
            return $return;
        } catch (InvalidUserConfigurationException $e) {
            $return['status'] = false;
            $return['message'] = "MID configuration on SIM card differs from what's configured on provider's side.";
            return $return;
        } catch (MidSessionNotFoundException | MissingOrInvalidParameterException | UnauthorizedException $e) {
            $return['status'] = false;
            $return['message'] = "Client side error with mobile-ID integration. Error code:" . $e->getCode();
            return $return;
        } catch (NotMidClientException $e) {
            // if user is not MID client then this exception is thrown and caught already during first request
            $return['status'] = false;
            $return['message'] = "You are not a Mobile-ID client or your Mobile-ID certificates are revoked.";
            return $return;
        } catch (MidInternalErrorException $internalError) {
            $return['status'] = false;
            $return['message'] = "Something went wrong with Mobile-ID service";
            return $return;
        }

        # step #9 - read out authenticated person details
        $return['status'] = true;
        $return['finished'] = true;
        $return['message'] = "All good";
        $return["firstName"] = $authenticatedPerson->getGivenName();
        $return["lastName"] = $authenticatedPerson->getSurName();
        $return["socialSecurityNumber"] = $authenticatedPerson->getIdentityCode();
        $return["country"] = $authenticatedPerson->getCountry();
        return $return;
    }
}
