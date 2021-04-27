# aws-del-user

aws-del-user is the tool for deleting IAM User and dependency resources.

## Usage

```sh
# Delete user01 and user02
$ aws-del-user user01 user02

# Delete resources depending on user01 without Login Profile and User.
# You use it if you managed IAM User and Login Profile by such as CloudFormation.
$ aws-del-user --skip u,lp user01
```

## Install

```sh
$ go install github.com/x-color/aws-del-user
```
