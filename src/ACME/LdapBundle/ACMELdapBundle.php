<?php

namespace ACME\LdapBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;
use ACME\LdapBundle\DependencyInjection\Security\Factory\SecurityFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class ACMELdapBundle extends Bundle
{
	/*public function build(ContainerBuilder $container) {
		parent::build($container);
	
		$extension = $container->getExtension('security');
		$extension->addSecurityListenerFactory(new SecurityFactory());
	}*/
}
