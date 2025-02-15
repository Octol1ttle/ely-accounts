<?php
declare(strict_types=1);

namespace api\tests\functional\dev\applications;

use api\tests\FunctionalTester;

final class ResetClientCest {

    public function testReset(FunctionalTester $I): void {
        $I->amAuthenticated('TwoOauthClients');
        $I->sendPOST('/api/v1/oauth2/first-test-oauth-client/reset');
        $I->canSeeResponseCodeIs(200);
        $I->canSeeResponseIsJson();
        $I->canSeeResponseContainsJson([
            'success' => true,
            'data' => [
                'clientId' => 'first-test-oauth-client',
                'clientSecret' => 'Zt1kEK7DQLXXYISLDvURVXK32Q58sHWSFKyO71iCIlv4YM2IHlLbhsvYoIJScUzT',
                'name' => 'First test oauth client',
                'description' => 'Some description to the first oauth client',
                'redirectUri' => 'http://some-site-1.com/oauth/ely',
                'websiteUrl' => '',
                'countUsers' => 0,
                'createdAt' => 1519487434,
            ],
        ]);
    }

    public function testResetWithSecretChanging(FunctionalTester $I): void {
        $I->amAuthenticated('TwoOauthClients');
        $I->sendPOST('/api/v1/oauth2/first-test-oauth-client/reset?regenerateSecret');
        $I->canSeeResponseCodeIs(200);
        $I->canSeeResponseIsJson();
        $I->canSeeResponseContainsJson([
            'success' => true,
            'data' => [
                'clientId' => 'first-test-oauth-client',
                'name' => 'First test oauth client',
                'description' => 'Some description to the first oauth client',
                'redirectUri' => 'http://some-site-1.com/oauth/ely',
                'websiteUrl' => '',
                'countUsers' => 0,
                'createdAt' => 1519487434,
            ],
        ]);
        $I->canSeeResponseJsonMatchesJsonPath('$.data.clientSecret');
        $secret = $I->grabDataFromResponseByJsonPath('$.data.clientSecret')[0];
        $I->assertNotEquals('Zt1kEK7DQLXXYISLDvURVXK32Q58sHWSFKyO71iCIlv4YM2IHlLbhsvYoIJScUzT', $secret);
    }

}
