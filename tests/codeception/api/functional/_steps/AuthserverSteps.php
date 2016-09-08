<?php
namespace tests\codeception\api\functional\_steps;

use Ramsey\Uuid\Uuid;
use tests\codeception\api\_pages\AuthserverRoute;
use tests\codeception\api\FunctionalTester;

class AuthserverSteps extends FunctionalTester {

    public function amAuthenticated() {
        $route = new AuthserverRoute($this);
        $clientToken = Uuid::uuid4()->toString();
        $route->authenticate([
            'username' => 'admin',
            'password' => 'password_0',
            'clientToken' => $clientToken,
        ]);

        $accessToken = $this->grabDataFromResponseByJsonPath('$.accessToken')[0];

        return [$accessToken, $clientToken];
    }

}