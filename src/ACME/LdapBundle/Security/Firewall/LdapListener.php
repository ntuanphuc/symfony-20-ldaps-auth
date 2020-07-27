<?php

namespace ACME\LdapBundle\Security\Firewall;

use Doctrine\ORM\EntityManager;
use ACME\LdapBundle\Security\Adaptor\LdapAdaptor;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Log\LoggerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Role\SwitchUserRole;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use ACME\LdapBundle\Security\Authentication\Token\LdapUserToken;
use Symfony\Component\Security\Http\HttpUtils;

class LdapListener implements ListenerInterface
{
    protected $securityContext;
    protected $authenticationManager;
    protected $adaptor;
    protected $logger;
    protected $options;
    protected $successHandler;
    protected $authChecker;
    protected $httpUtils;
    
    private $accessDecisionManager;
    private $em;


    public function __construct(SecurityContextInterface $securityContext,
                                AuthenticationManagerInterface $authenticationManager,
                                LoggerInterface $logger,
                                LdapAdaptor $adaptor,
                                HttpUtils $httpUtils,
                                AccessDecisionManagerInterface $accessDecisionManager,
                                AuthenticationSuccessHandlerInterface $successHandler,
                                array $options = array(),
                                EntityManager $em
    )
    {
        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
        $this->adaptor = $adaptor;
        $this->logger = $logger;
        $this->httpUtils = $httpUtils;
        $this->options = $options;
        $this->successHandler = $successHandler;
        $this->accessDecisionManager = $accessDecisionManager;
        $this->em = $em;
    }

    public function handle(GetResponseEvent $event)
    {

        $request = $event->getRequest();

        //already authenticated
        if (!is_null($this->securityContext->getToken())
            && $this->securityContext->isGranted('IS_AUTHENTICATED_FULLY')
        ) {
            return;
        }
        // handle xmlrequest
        if ($request->isXmlHttpRequest()) {
            $response = new Response('You are logged out!');
            return $event->setResponse($response);
        }


        $method = $request->getMethod();
        
        //handle submit login
        if ($method == 'POST') {
            $token = new LdapUserToken();

            $username = strtolower(trim($request->request->get('_username'))); //username without @domain
            $password = trim($request->request->get('_password'));
            
            try {
                //remove domain
                /*if (preg_match('/@/', $username)) {
                    $dataArr = explode("@", $username);
                    $username = trim($dataArr[0]);
                }*/
                //authenticate with LDAP(s)
                $isValidAccount = $this->adaptor->authenticate($username, $password);
            } catch (\Exception $e) {
                @ob_end_clean();
                $this->logger->crit($e->getMessage() . "\n" . $e->getTraceAsString());
                $response = new Response('Access Denied');
                $response->setStatusCode(403);
                return $event->setResponse($response);
            }

            if ($isValidAccount) {
                $token->setUser($username);
                try {

                    $returnValue = $this->authenticationManager->authenticate($token);
                    if ($returnValue instanceof TokenInterface) {

                        $user = $returnValue->getUser();

                        $this->securityContext->setToken($returnValue);
                        $response = $this->successHandler->onAuthenticationSuccess($request, $token);

                        if (!$response instanceof Response) {
                            throw new \RuntimeException('Authentication Success Handler did not return a Response.');
                        }

                        return $event->setResponse($response);

                    } else if ($returnValue instanceof Response) {
                        return $event->setResponse($returnValue);
                    }
                } catch (AuthenticationException $e) {
                    //reset token to null
                    $this->securityContext->setToken(null);
                    return;
                }
            } else {
                //reset token to null
                $this->securityContext->setToken(null);
                return;
            }
        }
    }

    /**
     * Whether this request requires authentication.
     *
     * The default implementation only processed requests to a specific path,
     * but a subclass could change this to only authenticate requests where a
     * certain parameters is present.
     *
     * @param Request $request
     *
     * @return Boolean
     */
    protected function requiresAuthentication(Request $request)
    {
        return $this->httpUtils->checkRequestPath($request, $this->options['auth_path']);
    }

    

    /**
     * Attempts to exit from an already switched user.
     *
     * @param Request $request A Request instance
     *
     * @return TokenInterface The original TokenInterface instance
     */
    private function attemptExitUser(Request $request)
    {
        if (false === $original = $this->getOriginalToken($this->securityContext->getToken())) {
            throw new AuthenticationCredentialsNotFoundException(sprintf('Could not find original Token object.'));
        }

        return $original;
    }

    /**
     * Gets the original Token from a switched one.
     *
     * @param TokenInterface $token A switched TokenInterface instance
     *
     * @return TokenInterface|false The original TokenInterface instance, false if the current TokenInterface is not switched
     */
    private function getOriginalToken(TokenInterface $token)
    {
        foreach ($token->getRoles() as $role) {
            //do something you need with role
            return $role->getSource();
            
        }

        return false;
    }
}