# javascript-collection
学习搜集js的常用例子与技术

##JS特效学习目录Special Effects
####SE1_bg_skin——PC背景换肤效果<br />
<p>
	<img src="http://img.blog.csdn.net/20160722120514093?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQv/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/Center" alt="" width="600px" height="300px" />
</p>
<p>
	<span style="font-family:Microsoft YaHei;font-size:14px;color:#cc33cc;"><em>点击换肤后效果如下：</em></span>
</p>
<p>
	<img src="http://img.blog.csdn.net/20160722121126186?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQv/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/Center" alt="" width="600px" height="300px" />
</p>
#jQuery studing.....<br />

<p>
	基本格式：
</p>
<p>
</p>
<pre name="code" class="javascript">&lt;script src=&quot;js/juery.js&quot; type=&quot;text/javascript&quot;&gt;&lt;/script&gt;
&lt;script src=&quot;js/input.js&quot; type=&quot;text/javascript&quot;&gt;&lt;/script&gt;</pre>
<pre name="code" class="javascript">$(&quot;document&quot;).ready(function(){
.....
});</pre>
<p>
</p>
<p>
	<br />
	
</p>
<p>
	input输入框设置格式：
</p>
（1）type: 一般设置成text,如果是密码则设置成password<br />
（2）autocomplete:自动补齐，关闭off &nbsp;否则会显示之前浏览器记录过的账号<br />
（3）placeholder：HTML5新增，设置输入框初始值。<br />
（4）onfocus: onfocus='if(this.value==&quot; 账号&quot;){this.value=&quot;&quot;;};' &nbsp;onblur='if(this.value==&quot;&quot;){this.value=&quot; 账号&quot;;};'设置焦点变化<br />
（5）type来回更改时，输入框密码和文字更替效果无法达到。<br />
解决方法：设置两个输入框进行show,hide操作<br />

<pre name="code" class="javascript">    $(&quot;#showpwd&quot;).focus(function(){
        $(&quot;#showpwd&quot;).hide();
        $(&quot;#pwd&quot;).show().focus();
    });
    $(&quot;#pwd&quot;).focus(function(){
        $(&quot;#pwd&quot;).attr({value:&quot;&quot;,type:&quot;password&quot;});
    });
    $(&quot;#pwd&quot;).blur(function(){
        var account=$(&quot;#pwd&quot;).val();
        var count=account.length;
        if(account==&quot;&quot;||account== null ||count== 0){
            if($(&quot;#pwd&quot;).attr(&quot;type&quot;)=='password') {
                $(&quot;#pwd&quot;).attr(&quot;type&quot;, &quot;text&quot;);
            }
            $(&quot;#pwd&quot;).attr(&quot;value&quot;,&quot; 密码不能为空&quot;);
        }
        else if(count&lt; 6){
            $(&quot;#pwd&quot;).attr(&quot;value&quot;,&quot;&quot;);
            $(&quot;#showpwd&quot;).show();
            $(&quot;#pwd&quot;).hide();
        }
    });</pre>
<br />
<br />
