package burp;

import java.awt.*;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, ITab, ISessionHandlingAction{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private CookieKillerTab cookieKillerTab;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("CookieKiller");

        // register ourselves as a session handling action
        callbacks.registerSessionHandlingAction(this);

        // add GUI tab
        cookieKillerTab = new CookieKillerTab(callbacks);
        callbacks.addSuiteTab(this);

        callbacks.printOutput("CookieKiller loaded");
    }

    @Override
    public String getTabCaption() { return "CookieKiller"; }

    @Override
    public Component getUiComponent() { return cookieKillerTab.$$$getRootComponent$$$(); }

    @Override
    public String getActionName() { return "CookieKiller"; }

    @Override
    public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {
        try {
            // value regex pattern
            Pattern rPattern;
            Matcher rMatch = null;

            // get cookies
            String[] cookies = cookieKillerTab.getCookies();

            // get headers
            burp.IRequestInfo requestInfo = helpers.analyzeRequest(currentRequest);
            java.util.List<String> headers = requestInfo.getHeaders();

            // find cookies header
            int index = -1;
            for(int i=0; i<headers.size(); i++){
                if (headers.get(i).toUpperCase().startsWith("COOKIE:")){
                    index = i;
                }
            }
            // can't find cookie header
            if(index == -1){
                return;
            }

            // split cookies into array
            String reqCookieString = headers.get(index).substring(7).trim();
            String[] reqCookieArray = reqCookieString.split("; {0,1}");
            ArrayList reqCookieArrayList = new ArrayList(Arrays.asList(reqCookieArray));

            // remove cookies
            for (Iterator<String> iterator = reqCookieArrayList.iterator(); iterator.hasNext();){
                String value = iterator.next();
                // if cookie doesn't contain equals, continue
                if(!value.contains("=")){
                    continue;
                }

                // get cookie name
                String cookieName = value.split("=")[0];
                for(String s : cookies){
                    if(cookieName.matches(s)){
                        iterator.remove();
                    }
                }
            }

            // set new cookie header
            headers.set(index, "Cookie: " + String.join("; ",reqCookieArrayList));

            // build new request
            byte[] requestBytes = currentRequest.getRequest();
            byte[] newRequestBytes = helpers.buildHttpMessage(headers, Arrays.copyOfRange(requestBytes, requestInfo.getBodyOffset(), requestBytes.length));
            currentRequest.setRequest(newRequestBytes);

        }catch(Exception e){
            printException(e);
        }
    }

    public void printException(Exception e) {
        callbacks.printOutput(e.toString());
        callbacks.printOutput(e.getMessage());
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        e.printStackTrace(pw);
        callbacks.printOutput(sw.toString());
    }
}
