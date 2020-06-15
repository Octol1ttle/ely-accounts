<?php
declare(strict_types=1);

namespace api\tests\unit\modules\accounts\models;

use api\modules\accounts\models\DeleteAccountForm;
use api\tests\unit\TestCase;
use common\models\Account;
use common\tasks\CreateWebHooksDeliveries;
use common\tasks\DeleteAccount;
use common\tests\fixtures\AccountFixture;
use ReflectionObject;
use Yii;
use yii\queue\Queue;

class DeleteAccountFormTest extends TestCase {

    /**
     * @var Queue|\PHPUnit\Framework\MockObject\MockObject
     */
    private Queue $queue;

    public function _fixtures(): array {
        return [
            'accounts' => AccountFixture::class,
        ];
    }

    public function _before(): void {
        parent::_before();

        $this->queue = $this->createMock(Queue::class);
        Yii::$app->set('queue', $this->queue);
    }

    public function testPerformAction() {
        /** @var Account $account */
        $account = $this->tester->grabFixture('accounts', 'admin');
        $this->queue
            ->expects($this->once())
            ->method('delay')
            ->with($this->equalToWithDelta(60 * 60 * 24 * 7, 5))
            ->willReturnSelf();
        $this->queue
            ->expects($this->exactly(2))
            ->method('push')
            ->withConsecutive(
                [$this->callback(function(CreateWebHooksDeliveries $task) use ($account): bool {
                    $this->assertSame($account->id, $task->payloads['id']);
                    return true;
                })],
                [$this->callback(function(DeleteAccount $task) use ($account): bool {
                    $obj = new ReflectionObject($task);
                    $property = $obj->getProperty('accountId');
                    $property->setAccessible(true);
                    $this->assertSame($account->id, $property->getValue($task));

                    return true;
                })],
            );

        $model = new DeleteAccountForm($account, [
            'password' => 'password_0',
        ]);
        $this->assertTrue($model->performAction());
        $this->assertSame(Account::STATUS_DELETED, $account->status);
        $this->assertEqualsWithDelta(time(), $account->deleted_at, 5);
    }

    public function testPerformActionWithInvalidPassword() {
        /** @var Account $account */
        $account = $this->tester->grabFixture('accounts', 'admin');
        $model = new DeleteAccountForm($account, [
            'password' => 'invalid password',
        ]);
        $this->assertFalse($model->performAction());
        $this->assertSame(['password' => ['error.password_incorrect']], $model->getErrors());
    }

    public function testPerformActionForAlreadyDeletedAccount() {
        /** @var Account $account */
        $account = $this->tester->grabFixture('accounts', 'deleted-account');
        $model = new DeleteAccountForm($account, [
            'password' => 'password_0',
        ]);
        $this->assertFalse($model->performAction());
        $this->assertSame(['account' => ['error.account_already_deleted']], $model->getErrors());
    }

}
