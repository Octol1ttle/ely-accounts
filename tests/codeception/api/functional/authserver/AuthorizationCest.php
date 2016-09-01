<?php
namespace tests\codeception\api\functional\authserver;

use tests\codeception\api\_pages\AuthserverRoute;
use Ramsey\Uuid\Uuid;
use tests\codeception\api\FunctionalTester;

class AuthorizationCest {

    /**
     * @var AuthserverRoute
     */
    private $route;

    public function _before(FunctionalTester $I) {
        $this->route = new AuthserverRoute($I);
    }

    public function byName(FunctionalTester $I) {
        $I->wantTo('authenticate by username and password');
        $this->route->authenticate([
            'username' => 'admin',
            'password' => 'password_0',
            'clientToken' => Uuid::uuid4()->toString(),
        ]);

        $this->testSuccessResponse($I);
    }

    public function byEmail(FunctionalTester $I) {
        $I->wantTo('authenticate by email and password');
        $this->route->authenticate([
            'username' => 'admin@ely.by',
            'password' => 'password_0',
            'clientToken' => Uuid::uuid4()->toString(),
        ]);

        $this->testSuccessResponse($I);
    }

    public function wrongArguments(FunctionalTester $I) {
        $I->wantTo('get error on wrong amount of arguments');
        $this->route->authenticate([
            'key' => 'value',
        ]);
        $I->canSeeResponseCodeIs(400);
        $I->canSeeResponseIsJson();
        $I->canSeeResponseContainsJson([
            'error' => 'IllegalArgumentException',
            'errorMessage' => 'credentials can not be null.',
        ]);
    }

    public function wrongNicknameAndPassword(FunctionalTester $I) {
        $I->wantTo('authenticate by username and password with wrong data');
        $this->route->authenticate([
            'username' => 'nonexistent_user',
            'password' => 'nonexistent_password',
            'clientToken' => Uuid::uuid4()->toString(),
        ]);
        $I->canSeeResponseCodeIs(401);
        $I->canSeeResponseIsJson();
        $I->canSeeResponseContainsJson([
            'error' => 'ForbiddenOperationException',
            'errorMessage' => 'Invalid credentials. Invalid nickname or password.',
        ]);
    }

    public function bannedAccount(FunctionalTester $I) {
        $I->wantTo('authenticate in suspended account');
        $this->route->authenticate([
            'username' => 'Banned',
            'password' => 'password_0',
            'clientToken' => Uuid::uuid4()->toString(),
        ]);
        $I->canSeeResponseCodeIs(401);
        $I->canSeeResponseContainsJson([
            'error' => 'ForbiddenOperationException',
            'errorMessage' => 'This account has been suspended.',
        ]);
    }

    private function testSuccessResponse(FunctionalTester $I) {
        $I->seeResponseCodeIs(200);
        $I->seeResponseIsJson();
        $I->canSeeResponseJsonMatchesJsonPath('$.accessToken');
        $I->canSeeResponseJsonMatchesJsonPath('$.clientToken');
        $I->canSeeResponseJsonMatchesJsonPath('$.availableProfiles[0].id');
        $I->canSeeResponseJsonMatchesJsonPath('$.availableProfiles[0].name');
        $I->canSeeResponseJsonMatchesJsonPath('$.availableProfiles[0].legacy');
        $I->canSeeResponseJsonMatchesJsonPath('$.selectedProfile.id');
        $I->canSeeResponseJsonMatchesJsonPath('$.selectedProfile.name');
        $I->canSeeResponseJsonMatchesJsonPath('$.selectedProfile.legacy');
    }

}
