# About
This is a AWS Lambda function for notifying receiving e-mail with Amazon SES to Slack.

# Usage
1. Create `config.ini` file.

    ```
    cp config.ini.sample config.ini
    ```

    ```
    [aws]
    backet = S3 backet name that you set at Amazon SES Rule Sets.

    [slack]
    hook_url = Slack Webhook URL created at Incoming WebHooks in Custom Integrations.
    api_token = Slack API Token created at Legacy tokens section in Legacy integrations page.
    channel = Slack channel name you want to notify.
    channel_id = Slack channel "ID" (not a name) you want to notify.
    icon_emoji = :robot_face: (option)
    attachment_color = #7e1083 (option)
    ```

2. Create Lambda function using this script and config file.

    ```
    LambdaFunction
    ├── config.ini
    └── lambda_function.py
    ```

3. Add this Lambda function as Lambda Action to Amazon SES Rule Sets.

# Features
- This function show only e-mail summary (From, Date, Subject, To) at Slack channel.
- The e-mail body will post in the thread of that summary post.

# Smaple
At the case that you forwarded an email you received via Gmail to an email address configured in Amazon SES, it will be notified to Slack as follows:

<img width="1065" alt="2019-05-31_104227" src="https://user-images.githubusercontent.com/9986092/58675892-3f7a7f80-8391-11e9-8953-a8662f740bb1.png">

# Run as CLI
You can run this function on the command line. 

```
$ python3 lambda_function.py {message_id}
```

For `{message_id}`, please pass a message ID generated using random alphanumeric generated issued by Amazon SES.
