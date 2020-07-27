<?php
namespace RMIT\LdapBundle\DependencyInjection\Security\Factory;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;

class LdapFactory implements SecurityFactoryInterface
{
    public function create(ContainerBuilder $container, $id, $config, $userProvider, $defaultEntryPoint)
    {
        $providerId = 'security.authentication.provider.ldap.'.$id;
        $container
            ->setDefinition($providerId, new DefinitionDecorator('ldap.security.authentication.provider'))
            ->replaceArgument(0, new Reference($userProvider))
        ;

        $successHandlerId = 'security.authentication.success_handler.'.$id.'.'.str_replace('-', '_', $this->getKey());
        $successHandler = $container->setDefinition($successHandlerId, new DefinitionDecorator('ldap.authentication.success_handler'));
        $successHandler->addMethodCall('setProviderKey', array($id));

        $listenerId = 'security.authentication.listener.ldap.'.$id;
        $listener = $container->setDefinition($listenerId, new DefinitionDecorator('ldap.security.authentication.listener'))
            ->replaceArgument(6, new Reference($successHandlerId))
        ;

        return array($providerId, $listenerId, $defaultEntryPoint);
    }

    public function getPosition()
    {
        return 'pre_auth';
    }

    public function getKey()
    {
        return 'ldap';
    }

    public function addConfiguration(NodeDefinition $node)
    {
    }
}