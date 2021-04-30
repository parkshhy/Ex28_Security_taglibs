<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>loginForm</title>
</head>
<body>
	<h1>loginForm.jsp</h1>
	
	<c:url value="j_spring_security_check" var="loginUrl"/>
	<form action="${loginUrl}" method="post">
		<c:if test="${param.error != null}">
			<p>
				Login Error!<br/>
				${error_message}	
			</p>
		</c:if>
	
	ID : <input type="text" name="j_username" value="${username}"><br/> <!-- 스프링 인증을 받을때 사용할 사용자 이름의 값을 받을 태그 이름을 지정한다 -->
	PW : <input type="text" name="j_password"><br/> <!-- 스프링 인증을 받을때 사용할 사용자 비밀번호의 값을 받을 태그 이름음 지정한다 -->
	
	<input type="submit" value="LOGIN"><br/>
	</form>
</body>
</html>