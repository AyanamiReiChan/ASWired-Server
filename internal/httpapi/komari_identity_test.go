package httpapi

import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "net/http"
 "net/http/httptest"
 "strings"
 "sync"
 "testing"
 "time"
 "github.com/AyanamiReiChan/ASWired-Server/internal/auth"
 "github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func bridgeRequest(t *testing.T,h http.Handler,secret,path string,input any)*httptest.ResponseRecorder{
 t.Helper();raw,err:=json.Marshal(input);if err!=nil{t.Fatal(err)};req:=httptest.NewRequest("POST","/api/internal/komari/"+path,bytes.NewReader(raw));req.Header.Set("Authorization","Bearer "+secret);req.Header.Set("Content-Type","application/json");out:=httptest.NewRecorder();h.ServeHTTP(out,req);return out
}
func TestUnifiedAccountsAndProbeSessions(t *testing.T){
 a,h,adminToken:=controllerFixture(t);ctx:=context.Background()
 a.Config.KomariPublicURL="https://probe.example.test";a.Config.KomariBridgeSecret=strings.Repeat("s",32);a.Config.AdminUsernames=[]string{"test-admin"}
 hash,err:=auth.HashPassword("probe-password-2026");if err!=nil{t.Fatal(err)}
 u:=store.User{ID:"probe-account",Username:"ProbeAdmin",PasswordHash:hash,Role:"user",TokenVersion:1}
 _,err=a.DB.SaveMemberRecord(ctx,u,store.Record{Collection:"members",ID:u.ID,OwnerID:u.ID,Data:map[string]any{"username":u.Username,"role":"成员","application":"komari"}},false);if err!=nil{t.Fatal(err)}
 // All account types share the same case-insensitive unique username index.
 err=a.DB.CreateUser(ctx,store.User{ID:"duplicate",Username:" probeADMIN ",Role:"user",PasswordHash:hash});if !errors.Is(err,store.ErrConflict){t.Fatalf("duplicate accepted: %v",err)}
 requireStatus(t,controllerRequest(t,h,"GET","/api/state",adminToken,nil),200)
 member:=store.User{ID:"ordinary",Username:"ordinary",PasswordHash:hash,Role:"user",TokenVersion:1};if err=a.DB.CreateUser(ctx,member);err!=nil{t.Fatal(err)}
 memberLogin:=controllerRequest(t,h,"POST","/api/login","",map[string]any{"username":"ordinary","password":"probe-password-2026"});requireStatus(t,memberLogin,200);memberToken:=text(responseMap(t,memberLogin),"token")
 requireStatus(t,controllerRequest(t,h,"GET","/api/state",memberToken,nil),200)
 requireStatus(t,controllerRequest(t,h,"GET","/api/logs/files",memberToken,nil),403)
 otherAdmin:=store.User{ID:"other-admin",Username:"other-admin",PasswordHash:hash,Role:"admin",TokenVersion:1};if err=a.DB.CreateUser(ctx,otherAdmin);err!=nil{t.Fatal(err)}
 requireStatus(t,controllerRequest(t,h,"POST","/api/login","",map[string]any{"username":"other-admin","password":"probe-password-2026"}),403)
 login:=controllerRequest(t,h,"POST","/api/login","",map[string]any{"username":" PROBEADMIN ","password":"probe-password-2026"});requireStatus(t,login,200);result:=responseMap(t,login)
 if result["kind"]!="komari"||result["token"]!=nil||result["action"]!="https://probe.example.test/auth/aswired/session"{t.Fatal("incorrect application routing",result)}
 ticket:=text(result,"ticket")
 requireStatus(t,bridgeRequest(t,h,"wrong","redeem",map[string]any{"ticket":ticket}),401)
 redeem:=bridgeRequest(t,h,a.Config.KomariBridgeSecret,"redeem",map[string]any{"ticket":ticket});requireStatus(t,redeem,200);session:=text(responseMap(t,redeem),"session")
 requireStatus(t,bridgeRequest(t,h,a.Config.KomariBridgeSecret,"redeem",map[string]any{"ticket":ticket}),401)
 requireStatus(t,bridgeRequest(t,h,a.Config.KomariBridgeSecret,"introspect",map[string]any{"session":session}),200)
 requireStatus(t,controllerRequest(t,h,"GET","/api/state",session,nil),401)
 signed,_:=a.Signer.Issue(u.ID,u.TokenVersion);requireStatus(t,controllerRequest(t,h,"GET","/api/state",signed,nil),403)
 requireStatus(t,bridgeRequest(t,h,a.Config.KomariBridgeSecret,"introspect",map[string]any{"session":memberToken}),401)
 u,err=a.DB.UserByID(ctx,u.ID);if err!=nil{t.Fatal(err)};u.Disabled=true;if err=a.DB.UpdateUser(ctx,u);err!=nil{t.Fatal(err)}
 requireStatus(t,bridgeRequest(t,h,a.Config.KomariBridgeSecret,"introspect",map[string]any{"session":session}),401)
}
func TestKomariTicketConcurrentRedemptionAndExpiry(t *testing.T){
 a,h,_:=controllerFixture(t);ctx:=context.Background();a.Config.KomariPublicURL="https://probe.example.test";a.Config.KomariBridgeSecret=strings.Repeat("s",32)
 u:=store.User{ID:"probe",Username:"probe",Role:"user",PasswordHash:"fixture",TokenVersion:1}
 if _,err:=a.DB.SaveMemberRecord(ctx,u,store.Record{Collection:"members",ID:u.ID,Data:map[string]any{"application":"komari"}},false);err!=nil{t.Fatal(err)}
 issue:=httptest.NewRecorder();a.issue(issue,u);ticket:=text(responseMap(t,issue),"ticket")
 statuses:=make(chan int,8);var group sync.WaitGroup
 for i:=0;i<8;i++{group.Add(1);go func(){defer group.Done();statuses<-bridgeRequest(t,h,a.Config.KomariBridgeSecret,"redeem",map[string]any{"ticket":ticket}).Code}()};group.Wait();close(statuses);success:=0
 for status:=range statuses{if status==200{success++}else if status!=401{t.Fatal(status)}};if success!=1{t.Fatalf("ticket redeemed %d times",success)}
 expired:=strings.Repeat("expired",8)
 if _,err:=a.DB.SaveRecord(ctx,store.Record{Collection:"_komariTickets",ID:hashOpaque(expired),OwnerID:u.ID,Data:map[string]any{"tokenVersion":1,"expiresAt":time.Now().Add(-time.Minute)}});err!=nil{t.Fatal(err)}
 requireStatus(t,bridgeRequest(t,h,a.Config.KomariBridgeSecret,"redeem",map[string]any{"ticket":expired}),401)
 a.maintainKomariSessions(ctx,time.Now());if _,err:=a.DB.GetRecord(ctx,"_komariTickets",hashOpaque(expired));!errors.Is(err,store.ErrNotFound){t.Fatal("expired ticket retained")}
}
