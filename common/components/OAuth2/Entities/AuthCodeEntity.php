<?php
declare(strict_types=1);

namespace common\components\OAuth2\Entities;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AuthCodeTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

final class AuthCodeEntity implements AuthCodeEntityInterface {
    use EntityTrait;
    use AuthCodeTrait;
    use TokenEntityTrait;

}
