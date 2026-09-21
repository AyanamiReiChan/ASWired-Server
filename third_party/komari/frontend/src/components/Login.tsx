import { useEffect, type ComponentProps } from "react";
import { Button, Text } from "@radix-ui/themes";
import { AccountProvider, useAccount } from "@/contexts/AccountContext";
import { useIdentityOptions } from "@/hooks/useIdentityOptions";
import StandaloneLogin from "./StandaloneLogin";

type LoginProps = ComponentProps<typeof StandaloneLogin>;

export default function Login(props: LoginProps) {
  const { options, failed } = useIdentityOptions();
  if (failed) return <Text color="red">统一登录服务暂不可用，请刷新重试。</Text>;
  if (!options) return <Button disabled>正在读取登录方式…</Button>;
  if (!options.enabled) return <StandaloneLogin {...props} />;
  return <AccountProvider><UnifiedLogin {...props} loginUrl={options.loginUrl} /></AccountProvider>;
}

function UnifiedLogin({ loginUrl, ...props }: LoginProps & { loginUrl: string }) {
  const { account, loading, error } = useAccount();
  const loggedIn = account?.logged_in === true;
  useEffect(() => {
    if (props.autoOpen && !loading && !error && !loggedIn) {
      window.location.replace(loginUrl);
    }
  }, [props.autoOpen, loading, error, loggedIn, loginUrl]);
  if (error) return <Text color="red">无法读取登录状态，请刷新重试。</Text>;
  if (loading) return <Button disabled>正在读取登录状态…</Button>;
  if (loggedIn && props.showSettings === false) return null;
  return <Button onClick={() => window.location.assign(loggedIn ? "/admin" : loginUrl)}>
    {loggedIn ? "管理面板" : props.trigger ?? "登录"}
  </Button>;
}
