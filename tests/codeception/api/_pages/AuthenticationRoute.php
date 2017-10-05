<?php
namespace tests\codeception\api\_pages;

class AuthenticationRoute extends BasePage {

    /**
     * @param string           $login
     * @param string           $password
     * @param string|bool|null $rememberMeOrToken
     * @param bool             $rememberMe
     */
    public function login($login = '', $password = '', $rememberMeOrToken = null, $rememberMe = false) {
        $params = [
            'login' => $login,
            'password' => $password,
        ];

        if ((is_bool($rememberMeOrToken) && $rememberMeOrToken) || $rememberMe) {
            $params['rememberMe'] = 1;
        } elseif ($rememberMeOrToken !== null) {
            $params['totp'] = $rememberMeOrToken;
        }

        $this->getActor()->sendPOST('/authentication/login', $params);
    }

    public function logout() {
        $this->getActor()->sendPOST('/authentication/logout');
    }

    public function forgotPassword($login = null, $token = null) {
        $this->getActor()->sendPOST('/authentication/forgot-password', [
            'login' => $login,
            'totp' => $token,
        ]);
    }

    public function recoverPassword($key = null, $newPassword = null, $newRePassword = null) {
        $this->getActor()->sendPOST('/authentication/recover-password', [
            'key' => $key,
            'newPassword' => $newPassword,
            'newRePassword' => $newRePassword,
        ]);
    }

    public function refreshToken($refreshToken = null) {
        $this->getActor()->sendPOST('/authentication/refresh-token', [
            'refresh_token' => $refreshToken,
        ]);
    }

}
