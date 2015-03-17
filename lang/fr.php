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
$phpmailer->Subject = "Panneau H&eacute;bergement R&eacute;initialiser mot de passe";
$phpmailer->Body = "Bonjour " . $result['ac_user_vc'] . ",
Vous, ou quelqu'un ce faisant passer pour vous, a demand&eacute; un lien de r&eacute;initialisation de mot de passe pour &ecirc;tre envoy&eacute; pour la connexion &agrave; votre panneau de commande de votre h&eacute;bergement web .
Si vous souhaitez proc&eacute;der &agrave; la r&eacute;initialisation du mot de passe sur votre compte, se il vous pla&icirc;t utiliser le lien ci-dessous pour &ecirc;tre redirig&eacute; vers la page de r&eacute;initialisation de mot de passe.
" . $protocol . ctrl_options::GetSystemOption('sentora_domain') . "/?resetkey=" . $randomkey . "
";
$phpmailer->AddAddress($result['ac_email_vc']);
$phpmailer->SendEmail();
runtime_hook::Execute('OnRequestForgotPassword');
}
}
?>
