<?php

namespace App\Http\Controllers;

use _PHPStan_9815bbba4\Nette\Schema\ValidationException;
use App\Models\Passkey;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Session;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;

class PasskeyController extends Controller
{

    public function authenticate( Request $request ) {

        $data = $request->validate([ 'answer' => ['required', 'json'] ]);

        $publicKeyCredential = (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))
            ->create()
            ->deserialize($data['answer'], PublicKeyCredential::class, 'json');


        if ( ! $publicKeyCredential->response instanceof AuthenticatorAssertionResponse) {
            return to_route('profile.edit')->withFragment('managePasskeys');
        }

        $csmFactory = (new CeremonyStepManagerFactory)->requestCeremony();

        $passkey = Passkey::firstWhere('credential_id', $publicKeyCredential->rawId);

        if ( ! $passkey ) {
            throw \Illuminate\Validation\ValidationException::withMessages([
                'answer' => 'This passkey is not valid'
            ]);
        }

        try{
            $publicKeyCredentialSource = AuthenticatorAssertionResponseValidator::create($csmFactory)->check(
                publicKeyCredentialSource: $passkey->data,
                authenticatorAssertionResponse: $publicKeyCredential->response,
                publicKeyCredentialRequestOptions: Session::get('passkey-authentication-options'),
                host: $request->getHost(),
                userHandle: null,
            );
        } catch (\Exception $e){
            throw \Illuminate\Validation\ValidationException::withMessages([
                'answer' => 'This passkey is not valid'
            ]);
        }

        $passkey->update([
            'data' => $publicKeyCredentialSource
        ]);

        Auth::loginUsingId($passkey->user_id);
        $request->session()->regenerate();

        return to_route('dashboard');
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $data = $request->validateWithBag('createPasskey',[
            'name' => ['required', 'string', 'max:255'],
            'passkey' => ['required', 'json']
        ]);
        $publicKeyCredential = (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))
            ->create()
            ->deserialize($data['passkey'], PublicKeyCredential::class, 'json');


        if ( ! $publicKeyCredential->response instanceof AuthenticatorAttestationResponse) {
            return to_route('login');
        }


        $csmFactory = (new CeremonyStepManagerFactory)->creationCeremony();

        try{
            $publicKeyCredentialSource = AuthenticatorAttestationResponseValidator::create($csmFactory)->check(
                authenticatorAttestationResponse: $publicKeyCredential->response,
                publicKeyCredentialCreationOptions: Session::get('passkey-registration-options'),
                host: $request->getHost(),
            );
        } catch (\Exception $e){
            throw \Illuminate\Validation\ValidationException::withMessages([
                'name' => 'The given passkey is invalid'
            ])->errorBag('createPasskey');
        }

        $request->user()->passkeys()->create([
            'name' => $data['name'], // Maybe should be unique
            'data' => $publicKeyCredentialSource,
        ]);


        return to_route('profile.edit')->withFragment('managePasskeys');
    }


    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Passkey $passkey)
    {
        Gate::authorize('delete', $passkey);

        $passkey->delete();

        return to_route('profile.edit')->withFragment('managePasskeys');
    }
}
