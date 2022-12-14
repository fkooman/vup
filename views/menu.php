<?php declare(strict_types=1); ?>
<?php /** @var \Vpn\Portal\Tpl $this */?>
<?php /** @var bool $isAdmin */?>
<?php /** @var string $activeItem */?>
<?php
$menuItems = [
    'home' => $this->t('Home'),
    'account' => $this->t('Account'),
];
if ($isAdmin) {
    $menuItems['connections'] = $this->t('Connections');
    $menuItems['users'] = $this->t('Users');
    $menuItems['info'] = $this->t('Info');
    $menuItems['stats'] = $this->t('Stats');
    $menuItems['log'] = $this->t('Log');
}
?>
<ul>
<?php foreach ($menuItems as $menuKey => $menuText): ?>
<?php if ($menuKey === $activeItem): ?>
    <li class="active">
<?php else: ?>
    <li>
<?php endif; ?>
        <a href="<?=$this->e($menuKey); ?>"><?=$menuText; ?></a>
    </li>
<?php endforeach; ?>
</ul>
