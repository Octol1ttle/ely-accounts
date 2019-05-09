<?php
namespace api\tests\_support\models\authentication;

use api\components\ReCaptcha\Validator as ReCaptchaValidator;
use api\models\authentication\RepeatAccountActivationForm;
use api\tests\unit\TestCase;
use Codeception\Specify;
use common\models\EmailActivation;
use common\tasks\SendRegistrationEmail;
use common\tests\fixtures\AccountFixture;
use common\tests\fixtures\EmailActivationFixture;
use GuzzleHttp\ClientInterface;
use Yii;

class RepeatAccountActivationFormTest extends TestCase {
    use Specify;

    protected function setUp() {
        parent::setUp();
        Yii::$container->set(ReCaptchaValidator::class, new class(mock(ClientInterface::class)) extends ReCaptchaValidator {
            public function validateValue($value) {
                return null;
            }
        });
    }

    public function _fixtures() {
        return [
            'accounts' => AccountFixture::class,
            'activations' => EmailActivationFixture::class,
        ];
    }

    public function testValidateEmailForAccount() {
        $this->specify('error.email_not_found if passed valid email, but it don\'t exists in database', function() {
            $model = new RepeatAccountActivationForm(['email' => 'me-is-not@exists.net']);
            $model->validateEmailForAccount('email');
            expect($model->getErrors('email'))->equals(['error.email_not_found']);
        });

        $this->specify('error.account_already_activated if passed valid email, but account already activated', function() {
            $fixture = $this->tester->grabFixture('accounts', 'admin');
            $model = new RepeatAccountActivationForm(['email' => $fixture['email']]);
            $model->validateEmailForAccount('email');
            expect($model->getErrors('email'))->equals(['error.account_already_activated']);
        });

        $this->specify('no errors if passed valid email for not activated account', function() {
            $fixture = $this->tester->grabFixture('accounts', 'not-activated-account');
            $model = new RepeatAccountActivationForm(['email' => $fixture['email']]);
            $model->validateEmailForAccount('email');
            expect($model->getErrors('email'))->isEmpty();
        });
    }

    public function testValidateExistsActivation() {
        $this->specify('error.recently_sent_message if passed email has recently sent message', function() {
            $fixture = $this->tester->grabFixture('activations', 'freshRegistrationConfirmation');
            $model = $this->createModel(['emailKey' => $fixture['key']]);
            $model->validateExistsActivation('email');
            expect($model->getErrors('email'))->equals(['error.recently_sent_message']);
        });

        $this->specify('no errors if passed email has expired activation message', function() {
            $fixture = $this->tester->grabFixture('activations', 'oldRegistrationConfirmation');
            $model = $this->createModel(['emailKey' => $fixture['key']]);
            $model->validateExistsActivation('email');
            expect($model->getErrors('email'))->isEmpty();
        });
    }

    public function testSendRepeatMessage() {
        $model = new RepeatAccountActivationForm();
        $this->assertFalse($model->sendRepeatMessage(), 'no magic if we don\'t pass validation');
        $this->assertEmpty($this->tester->grabQueueJobs());

        /** @var \common\models\Account $account */
        $account = $this->tester->grabFixture('accounts', 'not-activated-account-with-expired-message');
        $model = new RepeatAccountActivationForm(['email' => $account->email]);
        $this->assertTrue($model->sendRepeatMessage());
        $activation = $model->getActivation();
        $this->assertNotNull($activation);
        /** @var SendRegistrationEmail $job */
        $job = $this->tester->grabLastQueuedJob();
        $this->assertInstanceOf(SendRegistrationEmail::class, $job);
        $this->assertSame($account->username, $job->username);
        $this->assertSame($account->email, $job->email);
        $this->assertSame($account->lang, $job->locale);
        $this->assertSame($activation->key, $job->code);
        $this->assertSame('http://localhost/activation/' . $activation->key, $job->link);
    }

    /**
     * @param array $params
     * @return RepeatAccountActivationForm
     */
    private function createModel(array $params = []) {
        return new class($params) extends RepeatAccountActivationForm {
            public $emailKey;

            public function getActivation() {
                return EmailActivation::findOne($this->emailKey);
            }
        };
    }

}