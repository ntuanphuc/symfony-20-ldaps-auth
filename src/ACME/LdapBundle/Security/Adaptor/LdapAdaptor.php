<?php

namespace ACME\LdapBundle\Security\Adaptor;

use Symfony\Component\HttpKernel\Log\LoggerInterface;

class LdapAdaptor
{
    private $options;
    private $logger;
    private $option_keys = array('ldap_host', /*'ldap_dn',*/
        'ldap_port', 'ldap_user_domain');

    public function __construct(array $options, LoggerInterface $logger)
    {
        foreach ($this->option_keys as $key) {
            if (empty($options[$key])) {
                throw new \Exception('Please specify ' . $key . ' for LDAP connection');
            }
        }
        $this->options = $options;
        $this->logger = $logger;
    }

    /**
     * authenticate user with ldap server
     * @param string $username
     * @param string $password
     * @return boolean
     */
    public function authenticate($username, $password)
    {
        $password = trim($password);
        if ($password == '') return false;

        $ldap_host = $this->options['ldap_host'];
        $ldap_port = $this->options['ldap_port'];
        //$ldap_dn = $this->options['ldap_dn'];
        $ldap_user_domain = $this->options['ldap_user_domain'];
        $authen_name = $username . '@' . $ldap_user_domain;

        $ldapLink = @ldap_connect($ldap_host . ':' . $ldap_port);

        ldap_set_option($ldapLink, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($ldapLink, LDAP_OPT_REFERRALS, 0);

        $ldapBind = @ldap_bind($ldapLink, $authen_name, $password);

        if (!$ldapBind) {
            return false;
        } else {
            return true;
        }
    }

}