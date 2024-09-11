<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Passkey;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Str;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

class PasskeyController extends Controller
{
    public function registerOptions( Request $request){
        //Validate the name is not empty here to nos store the passkey in 1Password and then get the error
        $request->validate(['name' => ['required', 'string', 'max:255']]);

        $options = new PublicKeyCredentialCreationOptions(
            rp: new PublicKeyCredentialRpEntity(
                name: config('app.name'),
                id: parse_url(config('app.url'), PHP_URL_HOST),

            ),
            user: new PublicKeyCredentialUserEntity(
                name: $request->user()->email,
                id: $request->user()->id, // Shall not contain any personal information
                displayName: $request->user()->name
            ),
            challenge: Str::random(),
            authenticatorSelection: new AuthenticatorSelectionCriteria(
                authenticatorAttachment: AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
                  residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            ),
        );


        // More info: https://webauthn-doc.spomky-labs.com/pure-php/input-loading
        Session::flash('passkey-registration-options', $options);


        return (new WebauthnSerializerFactory(
            AttestationStatementSupportManager::create()
        ))->create()->serialize(
            $options,
            'json',
            [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                JsonEncode::OPTIONS => JSON_THROW_ON_ERROR,
            ]
        );
    }

    public function authenticateOptions(Request $request){

        $allowedCredentials = $request->filled('email')
            ? Passkey::whereRelation('user', 'email', $request->email )
                ->get()
                ->map(fn (Passkey $passkey) => $passkey->data )
                ->map( fn (PublicKeyCredentialSource $credential) => $credential->getPublicKeyCredentialDescriptor())
                ->all()
            : [];

        $options = new PublicKeyCredentialRequestOptions(
            challenge: Str::random(),
            rpId: parse_url(config('app.url'), PHP_URL_HOST),
            allowCredentials:$allowedCredentials,
        );

        Session::flash('passkey-authentication-options', $options);

        return (new WebauthnSerializerFactory(
            AttestationStatementSupportManager::create()
        ))->create()->serialize(data: $options, format: 'json');


    }
}
