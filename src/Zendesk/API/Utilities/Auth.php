<?php

namespace Zendesk\API\Utilities;

use Psr\Http\Message\RequestInterface;
use Zendesk\API\Exceptions\AuthException;

/**
 * Class Auth
 * This helper would manage all Authentication related operations.
 */
class Auth
{
    /**
    * The authentication setting to use an OAuth Token, with Impersonation.
    */
    const IMP = 'imp';
    /**
     * The authentication setting to use an OAuth Token.
     */
    const OAUTH = 'oauth';
    /**
     * The authentication setting to use Basic authentication with a username and API Token.
     */
    const BASIC = 'basic';

    /**
     * @var string
     */
    protected $authStrategy;

    /**
     * @var array
     */
    protected $authOptions;

    /**
     * Returns an array containing the valid auth strategies
     *
     * @return array
     */
    protected static function getValidAuthStrategies()
    {
        return [self::BASIC, self::OAUTH, self::IMP];
    }

    /**
     * Auth constructor.
     *
     * @param       $strategy
     * @param array $options
     *
     * @throws AuthException
     *
     */
    public function __construct($strategy, array $options)
    {
        if (! in_array($strategy, self::getValidAuthStrategies())) {
            throw new AuthException('Invalid auth strategy set, please use `'
                                    . implode('` or `', self::getValidAuthStrategies())
                                    . '`');
        }

        $this->authStrategy = $strategy;

        if ($strategy == self::BASIC) {
            if (! array_key_exists('username', $options) || ! array_key_exists('token', $options)) {
                throw new AuthException('Please supply `username` and `token` for basic auth.');
            }
        } elseif ($strategy == self::OAUTH) {
            if (! array_key_exists('token', $options)) {
                throw new AuthException('Please supply `token` for oauth.');
            }
        } elseif ($strategy == self::IMP){
            if(! array_key_exists('user_id', $options) || ! array_key_exists('token', $options)) {
                throw new AuthException('Please supply `user_id` and `token` for imp auth.');
            }
        }

        $this->authOptions = $options;
    }

    /**
     * @param RequestInterface $request
     * @param array            $requestOptions
     *
     * @return array
     * @throws AuthException
     */
    public function prepareRequest(RequestInterface $request, array $requestOptions = [])
    {
        if ($this->authStrategy === self::BASIC) {
            $requestOptions = array_merge($requestOptions, [
                'auth' => [
                    $this->authOptions['username'] . '/token',
                    $this->authOptions['token'],
                    'basic'
                ]
            ]);
        } elseif ($this->authStrategy === self::OAUTH) {
            $oAuthToken = $this->authOptions['token'];
            $request    = $request->withAddedHeader('Authorization', ' Bearer ' . $oAuthToken);
        } elseif($this->authStrategy === self::IMP){
            $oAuthToken = $this->authOptions['token'];
            $userId     = $this->authOptions['user_id'];
            $request    = $request->withAddedHeader('Authorization', ' Bearer ' . $oAuthToken);
            $request    = $request->withAddedHeader('X-On-Behalf-Of', $userId);
        } else {
            throw new AuthException('Please set authentication to send requests.');
        }

        return [$request, $requestOptions];
    }
}
