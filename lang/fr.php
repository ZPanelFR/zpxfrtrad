<?php
if (isset($_POST['inForgotPassword'])) {
runtime_csfr::Protect();
$randomkey = runtime_randomstring::randomHash();
$forgotPass = runtime_xss::xssClean($_POST['inForgotPassword']);
$sth = $zdbh->prepare("SELECT ac_id_pk, ac_user_vc, ac_email_vc FROM x_accounts WHERE ac_email_vc = :forgotPass AND ac_deleted_ts IS NULL");
$sth->bindParam(':forgotPass', $forgotPass);
$sth->execute();
$rows = $sth->fetchAll();
if ($rows) {
$result = $rows['0'];
$zdbh->exec("UPDATE x_accounts SET ac_resethash_tx = '" . $randomkey . "' WHERE ac_id_pk=" . $result['ac_id_pk'] . "");
if (isset($_SERVER['HTTPS'])) {
$protocol = 'https://';
} else {
$protocol = 'http://';
}
$phpmailer = new sys_email();
$phpmailer->Subject = "Panneau Hébergement Réinitialiser mot de passe";
$phpmailer->Body = "Bonjour " . $result['ac_user_vc'] . ",
Vous, ou quelqu'un faisant passer pour vous, a demandé un lien de réinitialisation de mot de passe pour être envoyé pour la connexion à votre panneau de commande de votre hébergement web .
Si vous souhaitez procéder à la réinitialisation du mot de passe sur votre compte, se il vous plaît utiliser le lien ci-dessous pour être redirigé vers la page de réinitialisation de mot de passe.
" . $protocol . ctrl_options::GetSystemOption('sentora_domain') . "/?resetkey=" . $randomkey . "
";
$phpmailer->AddAddress($result['ac_email_vc']);
$phpmailer->SendEmail();
runtime_hook::Execute('OnRequestForgotPassword');
}
}
?>
