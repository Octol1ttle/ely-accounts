<?php
namespace common\tests\_support;

use Codeception\Module;
use Codeception\TestInterface;
use common\tests\fixtures\AccountFixture;
use common\tests\fixtures\AccountSessionFixture;
use common\tests\fixtures\EmailActivationFixture;
use common\tests\fixtures\MinecraftAccessKeyFixture;
use common\tests\fixtures\OauthClientFixture;
use common\tests\fixtures\OauthSessionFixture;
use common\tests\fixtures\UsernameHistoryFixture;
use yii\test\FixtureTrait;
use yii\test\InitDbFixture;

/**
 * This helper is used to populate the database with needed fixtures before any tests are run.
 * All fixtures will be loaded before the suite is started and unloaded after it completes.
 *
 * TODO: try to remove
 */
class FixtureHelper extends Module {

    /**
     * Redeclare visibility because codeception includes all public methods that do not start with "_"
     * and are not excluded by module settings, in actor class.
     */
    use FixtureTrait {
        loadFixtures as protected;
        fixtures as protected;
        globalFixtures as protected;
        unloadFixtures as protected;
        getFixtures as protected;
        getFixture as protected;
    }

    public function _before(TestInterface $test) {
        $this->loadFixtures();
    }

    public function _after(TestInterface $test) {
        $this->unloadFixtures();
    }

    public function globalFixtures() {
        return [
            InitDbFixture::class,
        ];
    }

    public function fixtures() {
        return [
            'accounts' => AccountFixture::class,
            'accountSessions' => AccountSessionFixture::class,
            'emailActivations' => EmailActivationFixture::class,
            'usernamesHistory' => UsernameHistoryFixture::class,
            'oauthClients' => OauthClientFixture::class,
            'oauthSessions' => OauthSessionFixture::class,
            'minecraftAccessKeys' => MinecraftAccessKeyFixture::class,
        ];
    }

}