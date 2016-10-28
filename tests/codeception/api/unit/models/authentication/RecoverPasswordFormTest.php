<?php
namespace tests\codeception\api\models\authentication;

use api\components\User\LoginResult;
use api\models\authentication\RecoverPasswordForm;
use Codeception\Specify;
use common\models\Account;
use common\models\EmailActivation;
use tests\codeception\api\unit\TestCase;
use tests\codeception\common\fixtures\EmailActivationFixture;

class RecoverPasswordFormTest extends TestCase {
    use Specify;

    public function _fixtures() {
        return [
            'emailActivations' => EmailActivationFixture::class,
        ];
    }

    public function testRecoverPassword() {
        $fixture = $this->tester->grabFixture('emailActivations', 'freshPasswordRecovery');
        $model = new RecoverPasswordForm([
            'key' => $fixture['key'],
            'newPassword' => '12345678',
            'newRePassword' => '12345678',
        ]);
        $result = $model->recoverPassword();
        $this->assertInstanceOf(LoginResult::class, $result);
        $this->assertNull($result->getSession(), 'session was not generated');
        $this->assertFalse(EmailActivation::find()->andWhere(['key' => $fixture['key']])->exists());
        /** @var Account $account */
        $account = Account::findOne($fixture['account_id']);
        $this->assertTrue($account->validatePassword('12345678'));
    }

}
