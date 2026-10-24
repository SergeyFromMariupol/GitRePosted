<?php
declare(strict_types=1);
require dirname(__DIR__).'/bin/application.php';
$failures=0;$groups=0;
function check(bool $ok,string $why='assertion failed'):void{if(!$ok)throw new RuntimeException($why);}
function group(string $name,callable $test):void{global $failures,$groups;++$groups;try{$test();echo "PASS $name\n";}catch(Throwable $e){++$failures;echo "FAIL $name: ".$e->getMessage()."\n";}}
function app(object $fixture):InstallerApplication{return call_user_func($fixture->make);}
function fixture():object{
 $f=(object)['calls'=>[],'tg'=>[],'max'=>[],'schema'=>[],'fail'=>false];
 $f->config=['bot_token'=>'123456:'.str_repeat('a',32),'bot_username'=>'fixture_bot','telegram_bot_enabled'=>false,
  'max_bot_token'=>'fixture-max-token','max_bot_username'=>'fixture_max','max_bot_enabled'=>false,
  'base_url'=>'https://bridge.example','webhook_secret'=>str_repeat('b',64),'max_webhook_secret'=>str_repeat('c',64)];
 $f->transport=static function($platform,$token,$method,$path,$body,$attempts)use($f){
  $f->calls[]=compact('platform','method','path','body','attempts');
  if($f->fail)throw new RuntimeException('private '.$token);
  if($path==='getMe')return ['ok'=>true,'result'=>['id'=>123456,'is_bot'=>true,'username'=>'fixture_bot']];
  if($path==='/me')return ['user_id'=>77,'username'=>'fixture_max'];
  if($path==='getWebhookInfo')return ['ok'=>true,'result'=>$f->tg[0]??['url'=>'']];
  if($path==='/subscriptions'&&$method==='GET')return ['subscriptions'=>$f->max];
  if($path==='setWebhook'){$f->tg=[['url'=>$body['url'],'allowed_updates'=>$body['allowed_updates']]];return ['ok'=>true,'result'=>true];}
  if($path==='/subscriptions'&&$method==='POST'){$f->max[]=['url'=>$body['url'],'update_types'=>$body['update_types']];return ['success'=>true];}
  if($path==='/subscriptions'&&$method==='DELETE'){$f->max=array_values(array_filter($f->max,fn($row)=>$row['url']!==$body['url']));return ['success'=>true];}
  if($path==='/me/commands')return ['commands'=>$body['commands']];
  if(in_array($path,['setMyCommands','setChatMenuButton'],true))return ['ok'=>true,'result'=>true];
  throw new RuntimeException('unexpected provider call');
 };
 $f->make=static function(?array $cfg=null)use($f){return new InstallerApplication($f->transport,static function($action,$config)use($f){$f->schema[]=$action;return ['tables'=>19];},$cfg??$f->config);};
 return $f;
}
group('check token uses reads only and no schema',function(){foreach(['telegram','max'] as $platform){$f=fixture();$result=app($f)->run(['action'=>'check','platform'=>$platform,'token'=>$f->config[$platform==='telegram'?'bot_token':'max_bot_token']]);check($result['ok']);check(count($f->calls)===2);check($f->schema===[]);foreach($f->calls as $c)check(in_array($c['path'],['getMe','getWebhookInfo','/me','/subscriptions'],true));}});
group('invalid platform and token fail before any API',function(){$f=fixture();foreach([['platform'=>'other','token'=>'x'],['platform'=>'telegram','token'=>'bad'],['platform'=>'max','token'=>"invalid\ntoken"]] as $input){$result=app($f)->run(['action'=>'check']+$input);check(!$result['ok']);}check($f->calls===[]);});
group('initialize needs paused config and never queries platform',function(){$f=fixture();$app=app($f);check($app->run(['action'=>'initialize','config'=>$f->config])['ok']);check($f->schema===['initialize']);check($f->calls===[]);$active=$f->config;$active['telegram_bot_enabled']=true;check(!$app->run(['action'=>'initialize','config'=>$active])['ok']);check(count($f->schema)===1);});
group('admin only verification has no platform API effects',function(){$f=fixture();check(app($f)->run(['action'=>'verify','platforms'=>[]])['ok']);check($f->schema===['verify']);check($f->calls===[]);});
group('foreign webhook consent is mandatory before mutation',function(){foreach(['telegram','max'] as $platform){$f=fixture();$f->{$platform==='telegram'?'tg':'max'}=[['url'=>'https://other.example/private']];$result=app($f)->run(['action'=>'register','platform'=>$platform]);check(!$result['ok']&&$result['error']['code']==='TAKEOVER_REQUIRED');foreach($f->calls as $c)check(in_array($c['path'],['getMe','getWebhookInfo','/me','/subscriptions'],true)&&$c['method']!=='DELETE');}});
group('Telegram registration preserves pending queue and exact event set',function(){$f=fixture();check(app($f)->run(['action'=>'register','platform'=>'telegram'])['ok']);$send=array_values(array_filter($f->calls,fn($c)=>$c['path']==='setWebhook'))[0];check($send['body']['url']==='https://bridge.example/webhooks/telegram');check($send['body']['drop_pending_updates']===false);check(in_array('edited_message',$send['body']['allowed_updates'],true));check(!in_array('chat_member',$send['body']['allowed_updates'],true));foreach($f->calls as $c)check($c['platform']==='telegram');});
group('MAX confirms new subscription before removing approved old URL',function(){$f=fixture();$f->max=[['url'=>'https://old.example/hook','update_types'=>[]]];check(app($f)->run(['action'=>'register','platform'=>'max','takeover'=>true])['ok']);$paths=array_map(fn($c)=>$c['method'].' '.$c['path'],$f->calls);$post=array_search('POST /subscriptions',$paths,true);$delete=array_search('DELETE /subscriptions',$paths,true);check(is_int($post)&&is_int($delete)&&$post<$delete);check(in_array('GET /subscriptions',array_slice($paths,$post+1,$delete-$post-1),true));check(count($f->max)===1&&$f->max[0]['url']==='https://bridge.example/webhooks/max');});
group('configured active workers prevent installer registration',function(){$f=fixture();$f->config['max_bot_enabled']=true;$result=app($f)->run(['action'=>'register','platform'=>'telegram']);check(!$result['ok']);check($f->calls===[]);});
group('private foreign URL components and API errors never leak',function(){$f=fixture();$secret='private-fixture-marker';$f->tg=[['url'=>'https://old.example/'.$secret.'?key='.$secret]];$result=app($f)->run(['action'=>'check','platform'=>'telegram','token'=>$f->config['bot_token']]);check($result['ok']);check(!str_contains(json_encode($result),$secret));$f->fail=true;$result=app($f)->run(['action'=>'check','platform'=>'telegram','token'=>$f->config['bot_token']]);check(!$result['ok']&&!str_contains(json_encode($result),$f->config['bot_token']));});
group('read-only installation state exposes only activation flags',function(){$f=fixture();$result=app($f)->run(['action'=>'installation_state']);check($result===['ok'=>true,'result'=>['configured'=>true,'telegram_enabled'=>false,'max_enabled'=>false]]);check($f->calls===[]&&$f->schema===[]);});
group('installed JSON activation flags must be present and strictly typed',function(){
 $path=tempnam(sys_get_temp_dir(),'grp-flags-');$previous=getenv('GITREPOSTED_ENV_FILE');putenv('GITREPOSTED_ENV_FILE='.$path);
 try{
  foreach([[],['GITREPOSTED_WORKERS_ENABLED'=>'0'],['GITREPOSTED_WORKERS_ENABLED'=>false,'TELEGRAM_ENABLED'=>'0','MAX_ENABLED'=>'0']] as $flat){file_put_contents($path,json_encode($flat));$r=(new InstallerApplication())->run(['action'=>'installation_state']);check(!$r['ok']&&$r['error']['code']==='CONFIG_UNAVAILABLE');}
  file_put_contents($path,json_encode(['GITREPOSTED_WORKERS_ENABLED'=>'1','TELEGRAM_ENABLED'=>'1','MAX_ENABLED'=>'0']));
  check((new InstallerApplication())->run(['action'=>'installation_state'])===['ok'=>true,'result'=>['configured'=>true,'telegram_enabled'=>true,'max_enabled'=>false]]);
 }finally{unlink($path);$previous===false?putenv('GITREPOSTED_ENV_FILE'):putenv('GITREPOSTED_ENV_FILE='.$previous);}
});
echo "$groups application groups; failures=$failures\n";exit($failures?1:0);
