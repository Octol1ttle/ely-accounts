<?php
namespace codeception\api\unit\modules\authserver\models;

use api\models\authentication\LoginForm;
use api\modules\authserver\models\AuthenticateData;
use api\modules\authserver\models\AuthenticationForm;
use common\models\Account;
use common\models\MinecraftAccessKey;
use Ramsey\Uuid\Uuid;
use tests\codeception\api\unit\TestCase;
use tests\codeception\common\_support\ProtectedCaller;
use tests\codeception\common\fixtures\AccountFixture;
use tests\codeception\common\fixtures\MinecraftAccessKeyFixture;

class AuthenticationFormTest extends TestCase {
    use ProtectedCaller;

    public function _fixtures() {
        return [
            'accounts' => AccountFixture::class,
            'minecraftAccessKeys' => MinecraftAccessKeyFixture::class,
        ];
    }

    /**
     * @expectedException \api\modules\authserver\exceptions\ForbiddenOperationException
     * @expectedExceptionMessage Invalid credentials. Invalid nickname or password.
     */
    public function testAuthenticateByWrongNicknamePass() {
        $authForm = $this->createAuthForm();

        $authForm->username = 'wrong-username';
        $authForm->password = 'wrong-password';
        $authForm->clientToken = Uuid::uuid4();

        $authForm->authenticate();
    }

    /**
     * @expectedException \api\modules\authserver\exceptions\ForbiddenOperationException
     * @expectedExceptionMessage Invalid credentials. Invalid email or password.
     */
    public function testAuthenticateByWrongEmailPass() {
        $authForm = $this->createAuthForm();

        $authForm->username = 'wrong-email@ely.by';
        $authForm->password = 'wrong-password';
        $authForm->clientToken = Uuid::uuid4();

        $authForm->authenticate();
    }

    /**
     * @expectedException \api\modules\authserver\exceptions\ForbiddenOperationException
     * @expectedExceptionMessage This account has been suspended.
     */
    public function testAuthenticateByValidCredentialsIntoBlockedAccount() {
        $authForm = $this->createAuthForm(Account::STATUS_BANNED);

        $authForm->username = 'dummy';
        $authForm->password = 'password_0';
        $authForm->clientToken = Uuid::uuid4();

        $authForm->authenticate();
    }

    public function testAuthenticateByValidCredentials() {
        $authForm = $this->createAuthForm();

        $minecraftAccessKey = new MinecraftAccessKey();
        $minecraftAccessKey->access_token = Uuid::uuid4();
        $authForm->expects($this->once())
            ->method('createMinecraftAccessToken')
            ->will($this->returnValue($minecraftAccessKey));

        $authForm->username = 'dummy';
        $authForm->password = 'password_0';
        $authForm->clientToken = Uuid::uuid4();

        $result = $authForm->authenticate();
        $this->assertInstanceOf(AuthenticateData::class, $result);
        $this->assertEquals($minecraftAccessKey->access_token, $result->getMinecraftAccessKey()->access_token);
    }

    public function testCreateMinecraftAccessToken() {
        $authForm = new AuthenticationForm();
        $authForm->clientToken = Uuid::uuid4();
        /** @var Account $account */
        $account = $this->tester->grabFixture('accounts', 'admin');
        /** @var MinecraftAccessKey $result */
        $result = $this->callProtected($authForm, 'createMinecraftAccessToken', $account);
        $this->assertInstanceOf(MinecraftAccessKey::class, $result);
        $this->assertEquals($account->id, $result->account_id);
        $this->assertEquals($authForm->clientToken, $result->client_token);
        $this->assertInstanceOf(MinecraftAccessKey::class, MinecraftAccessKey::findOne($result->access_token));
    }

    public function testCreateMinecraftAccessTokenWithExistsClientId() {
        $authForm = new AuthenticationForm();
        $minecraftFixture = $this->tester->grabFixture('minecraftAccessKeys', 'admin-token');
        $authForm->clientToken = $minecraftFixture['client_token'];
        /** @var Account $account */
        $account = $this->tester->grabFixture('accounts', 'admin');
        /** @var MinecraftAccessKey $result */
        $result = $this->callProtected($authForm, 'createMinecraftAccessToken', $account);
        $this->assertInstanceOf(MinecraftAccessKey::class, $result);
        $this->assertEquals($account->id, $result->account_id);
        $this->assertEquals($authForm->clientToken, $result->client_token);
        $this->assertNull(MinecraftAccessKey::findOne($minecraftFixture['access_token']));
        $this->assertInstanceOf(MinecraftAccessKey::class, MinecraftAccessKey::findOne($result->access_token));
    }

    private function createAuthForm($status = Account::STATUS_ACTIVE) {
        /** @var LoginForm|\PHPUnit_Framework_MockObject_MockObject $loginForm */
        $loginForm = $this->getMockBuilder(LoginForm::class)
            ->setMethods(['getAccount'])
            ->getMock();

        $account = new Account();
        $account->username = 'dummy';
        $account->email = 'dummy@ely.by';
        $account->status = $status;
        $account->setPassword('password_0');

        $loginForm->expects($this->any())
            ->method('getAccount')
            ->will($this->returnValue($account));

        /** @var AuthenticationForm|\PHPUnit_Framework_MockObject_MockObject $authForm */
        $authForm = $this->getMockBuilder(AuthenticationForm::class)
            ->setMethods(['createLoginForm', 'createMinecraftAccessToken'])
            ->getMock();

        $authForm->expects($this->any())
            ->method('createLoginForm')
            ->will($this->returnValue($loginForm));

        return $authForm;
    }

}
