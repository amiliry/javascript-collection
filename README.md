# javascript-collection
学习搜集js的常用例子与技术

#jQuery studing.....
基本格式：
'''css
<script src="js/juery.js" type="text/javascript"></script>
<script src="js/input.js" type="text/javascript"></script>

$("document").ready(function(){
.....
});

-input输入框设置格式：<br>
（1）type: 一般设置成text,如果是密码则设置成password<br>
（2）autocomplete:自动补齐，关闭off  否则会显示之前浏览器记录过的账号<br>
（3）placeholder：HTML5新增，设置输入框初始值。<br>
（4）onfocus: onfocus='if(this.value==" 账号"){this.value="";};'  onblur='if(this.value==""){this.value=" 账号";};'设置焦点变化<br>
（5）type来回更改时，输入框密码和文字更替效果无法达到。<br>
解决方法：设置两个输入框进行show,hide操作<br>
'''jquery
    $("#showpwd").focus(function(){
        $("#showpwd").hide();
        $("#pwd").show().focus();
    });
    $("#pwd").focus(function(){
        $("#pwd").attr({value:"",type:"password"});
    });
    $("#pwd").blur(function(){
        var account=$("#pwd").val();
        var count=account.length;
        if(account==""||account== null ||count== 0){
            if($("#pwd").attr("type")=='password') {
                $("#pwd").attr("type", "text");
            }
            $("#pwd").attr("value"," 密码不能为空");
        }
        else if(count< 6){
            $("#pwd").attr("value","");
            $("#showpwd").show();
            $("#pwd").hide();
        }
    });
