<?php
declare(strict_types=1);

namespace api\tests\functional\dev\applications;

use api\tests\FunctionalTester;

final class UpdateClientCest {

    public function testUpdateWebApplication(FunctionalTester $I): void {
        $I->amAuthenticated('TwoOauthClients');
        $I->sendPUT('/api/v1/oauth2/first-test-oauth-client', [
            'name' => 'Updated name',
            'description' => 'Updated description.',
            'redirectUri' => 'http://new-site.com/oauth/ely',
            'websiteUrl' => 'http://new-site.com',
        ]);
        $I->canSeeResponseCodeIs(200);
        $I->canSeeResponseIsJson();
        $I->canSeeResponseContainsJson([
            'success' => true,
            'data' => [
                'clientId' => 'first-test-oauth-client',
                'clientSecret' => 'Zt1kEK7DQLXXYISLDvURVXK32Q58sHWSFKyO71iCIlv4YM2IHlLbhsvYoIJScUzT',
                'name' => 'Updated name',
                'description' => 'Updated description.',
                'redirectUri' => 'http://new-site.com/oauth/ely',
                'websiteUrl' => 'http://new-site.com',
                'createdAt' => 1519487434,
                'countUsers' => 0,
            ],
        ]);
    }

    public function testUpdateMinecraftServer(FunctionalTester $I): void {
        $I->amAuthenticated('TwoOauthClients');
        $I->sendPUT('/api/v1/oauth2/another-test-oauth-client', [
            'name' => 'Updated server name',
            'websiteUrl' => 'http://new-site.com',
            'minecraftServerIp' => 'hypixel.com:25565',
        ]);
        $I->canSeeResponseCodeIs(200);
        $I->canSeeResponseIsJson();
        $I->canSeeResponseContainsJson([
            'success' => true,
            'data' => [
                'clientId' => 'another-test-oauth-client',
                'clientSecret' => 'URVXK32Q58sHWSFKyO71iCIlv4YM2Zt1kEK7DQLXXYISLDvIHlLbhsvYoIJScUzT',
                'name' => 'Updated server name',
                'websiteUrl' => 'http://new-site.com',
                'minecraftServerIp' => 'hypixel.com:25565',
                'createdAt' => 1519487472,
            ],
        ]);
    }

}
