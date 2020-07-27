<?php
namespace ACME\LdapBundle\Security\Authentication\Provider;

use Monolog\Logger;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use ACME\LdapBundle\Security\Authentication\Token\LdapUserToken;
use Symfony\Component\HttpKernel\Log\LoggerInterface;

class LdapProvider implements AuthenticationProviderInterface
{
    private $userProvider;
    private $cacheDir;
    private $logger;

    public function __construct(UserProviderInterface $userProvider, $cacheDir, LoggerInterface $logger)
    {
        $this->userProvider = $userProvider;
        $this->cacheDir     = $cacheDir;
        $this->logger = $logger;
    }

    /**
     * This will be called if listener has success authorization
     * @param TokenInterface $token
     * @return LdapUserToken
     */
    public function authenticate(TokenInterface $token)
    {
        $user = $this->userProvider->loadUserByUsername($token->getUsername());
        //user logged in success, here we can do some validation if needed
        if ($user /*&& $this->validateDigest($token->digest, $token->nonce, $token->created, $user->getPassword())*/) {
            $authenticatedToken = new LdapUserToken($user->getRoles());
            $authenticatedToken->setUser($user);

            return $authenticatedToken;
        }
        throw new AuthenticationServiceException('The Ldap authentication failed.');
    }

    protected function validateDigest($digest, $nonce, $created, $secret)
    {
        // Check created time is not in the future
        //echo 'validate digest';exit;
        return true;
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof LdapUserToken;
    }
}