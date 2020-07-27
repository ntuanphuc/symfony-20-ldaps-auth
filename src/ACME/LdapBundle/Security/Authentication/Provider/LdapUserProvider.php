<?php
namespace ACME\LdapBundle\Security\Authentication\Provider;

use Doctrine\ORM\EntityManager;
#use Symfony\Component\Security\Core\Authentication\Provider\DaoAuthenticationProvider;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\HttpKernel\Log\LoggerInterface;

use ACME\UserBundle\Entity\User;

class LdapUserProvider  implements UserProviderInterface
{
    private $class;
    private $entityManager;
    private $metadata;
    private $logger;

    public function __construct(EntityManager $em, $class, LoggerInterface $logger)
    {
        $this->class = $class;
        $this->metadata = $em->getClassMetadata($class);

        if (false !== strpos($this->class, ':')) {
            $this->class = $this->metadata->name;
        }

        $this->entityManager = $em;
        $this->logger = $logger;
    }

    public function loadUserByUsername($username)
    {

        $user = $this->entityManager->getRepository($this->class)->find($username);

        if (!$user) {
            throw new AuthenticationServiceException('Your account does not exist');
        }

        if ($user->getIsActive() == User::INACTIVE) {
            throw new AuthenticationServiceException('Your account is not activated');
            //return false;
        }

        // roles
        
        $user->setRoles(array('ROLE_STAFF'));
        


        return $user;
    }

    public function refreshUser(UserInterface $user)
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }

        return $this->loadUserByUsername($user->getUsername());
    }

    public function supportsClass($class)
    {
        return $class === 'ACME\UserBundle\Entity\User';
    }
}