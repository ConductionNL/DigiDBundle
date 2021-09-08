<?php

// src/Security/TokenAuthenticator.php

/*
 * This authenticator authenticates against DigiSpoof
 *
 */

namespace App\Security;

use Conduction\CommonGroundBundle\Security\User\CommongroundUser;
use Conduction\CommonGroundBundle\Service\CommonGroundService;
use Doctrine\ORM\EntityManagerInterface;
use GuzzleHttp\Client;
use OneLogin\Saml2\Auth;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Symfony\Component\Serializer\Encoder\XmlEncoder;

class DigidAuthenticator extends AbstractGuardAuthenticator
{
    private ParameterBagInterface $parameterBagInterface;
    private CommonGroundService $commonGroundService;
    private RouterInterface $routerInterface;
    private UrlGeneratorInterface $urlGeneratorInterface;
    private SessionInterface $sessionInterface;
    private Auth $samlAuth;
    private XmlEncoder $xmlEncoder;

    public function __construct(ParameterBagInterface $parameterBagInterface, CommonGroundService $commonGroundService, RouterInterface $routerInterface, UrlGeneratorInterface $urlGeneratorInterface, SessionInterface $sessionInterface, Auth $samlAuth)
    {
        $this->parameterBagInterface = $parameterBagInterface;
        $this->commonGroundService = $commonGroundService;
        $this->routerInterface = $routerInterface;
        $this->urlGeneratorInterface = $urlGeneratorInterface;
        $this->sessionInterface = $sessionInterface;
        $this->samlAuth = $samlAuth;
        $this->xmlEncoder = new XmlEncoder(['xml_root_node_name' => 'md:EntityDescriptor']);
    }

    /**
     * Called on every request to decide if this authenticator should be
     * used for the request. Returning false will cause this authenticator
     * to be skipped.
     */
    public function supports(Request $request)
    {
        return 'app_default_samltest' === $request->attributes->get('_route')
            && $request->isMethod('GET');
    }

    /**
     * Called on every request. Return whatever credentials you want to
     * be passed to getUser() as $credentials.
     */
    public function getCredentials(Request $request)
    {
        $credentials = [
            'SAMLart'   => $request->query->get('SAMLart'),

        ];

        return $credentials;
    }

    public function samlartToBsn(string $artifact): string
    {
        $date = date('Y-m-d\TH:i:s\Z');
        $config = $this->samlAuth->getSettings()->getSPData();

        $xml = '
                <samlp:ArtifactResolve
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
        ID="_1330416073" Version="2.0" IssueInstant="'.$date.'">
        <saml:Issuer>'.$config['entityId'].'</saml:Issuer>
        <samlp:Artifact>'.$artifact.'</samlp:Artifact>
        </samlp:ArtifactResolve>';

        $signed = \OneLogin\Saml2\Utils::addSign($xml, $config['privateKey'], $config['x509cert']);
        $signed = str_replace('<?xml version="1.0"?>', '', $signed);

        $soap = '
        <soapenv:Envelope
        xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <soapenv:Body>
        '.$signed.'
        </soapenv:Body>
        </soapenv:Envelope>';


        $client = new Client([
            'base_uri' => 'https://was-preprod1.digid.nl',
            'timeout'  => 5.0,
            'ssl_key'  => $this->parameterBagInterface->get('app_ssl_key'),
            'cert'     => $this->parameterBagInterface->get('app_certificate'),
        ]);

        $response = $client->request('POST', '/saml/idp/resolve_artifact', [
            'headers' => [
                'Content-Type' => 'text/xml',
                'SOAPAction'   => $config['entityId'],
            ],
            'body' => $soap,
        ]);

        $result = $response->getBody()->getContents();

        $data = $this->xmlEncoder->decode($result, 'xml');

        $nameId = $data['soapenv:Body']['samlp:ArtifactResponse']['samlp:Response']['saml:Assertion']['saml:Subject']['saml:NameID'];
        $nameIdExplode = explode(":", $nameId);

        return end($nameIdExplode);
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $bsn = $this->samlartToBsn($credentials['SAMLart']);
        $this->sessionInterface->set('bsn', $bsn);

        // Aan de hand van BSN persoon ophalen uit haal centraal
        try {
            $user = $this->commonGroundService->getResource(['component' => 'brp', 'type' => 'ingeschrevenpersonen', 'id' => $bsn], [], false);
        } catch (\Throwable $e) {
            return;
        }

        if (!isset($user['roles'])) {
            $user['roles'] = [];
        }

        if (!in_array('ROLE_USER', $user['roles'])) {
            $user['roles'][] = 'ROLE_USER';
        }
        return new CommongroundUser($user['naam']['voornamen'], $user['naam']['voornamen'], $user['naam']['voornamen'], null, $user['roles'], $this->commonGroundService->cleanUrl(['component'=>'brp', 'type'=>'ingeschrevenpersonen', 'id' => $user['burgerservicenummer']]), null, 'person', false);
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        // no additional credential check is needed in this case so return true to cause authentication success
        return true;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        $bsn = $this->sessionInterface->get('bsn');
        $user = $this->commonGroundService->getResource(['component' => 'brp', 'type' => 'ingeschrevenpersonen', 'id' => $bsn]);

        $this->sessionInterface->set('user', $user);

        return new RedirectResponse($this->urlGeneratorInterface->generate('app_default_index'));
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return new RedirectResponse($this->parameterBagInterface->get('app_url').'/saml/Login');
    }

    /**
     * Called when authentication is needed, but it's not sent.
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        return new RedirectResponse($this->routerInterface->generate('app_user_digispoof', ['response' => $request->request->get('back_url'), 'back_url' => $request->request->get('back_url')]));
    }

    public function supportsRememberMe()
    {
        return true;
    }

    protected function getLoginUrl()
    {
        return $this->routerInterface->generate('app_user_digispoof', [], UrlGeneratorInterface::RELATIVE_PATH);
    }
}
