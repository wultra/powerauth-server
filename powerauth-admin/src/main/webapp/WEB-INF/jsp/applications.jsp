<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>

<c:choose>
    <c:when test="${fn:length(applications) == 0}">
        <jsp:include page="headerSimple.jsp">
            <jsp:param name="pageTitle" value="PowerAuth - Applications"/>
        </jsp:include>
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">New Application</h3>
            </div>
            <div class="panel-body">
                <form class="form-inline" action="${pageContext.request.contextPath}/application/create/do.submit"
                      method="POST">
                    Application ID: <input type="text" name="id" class="form-control">
                    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
                    <input type="submit" value="Submit" class="btn btn-success"/>
                </form>
            </div>
        </div>
    </c:when>
    <c:otherwise>
        <jsp:include page="header.jsp">
            <jsp:param name="pageTitle" value="PowerAuth - Applications"/>
        </jsp:include>
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title button-sm pull-left">Applications</h3>
                <a href="${pageContext.request.contextPath}/application/create" class="pull-right btn btn-sm btn-default">New
                    Application</a>
                <div class="clearfix"></div>
            </div>
            <table class="table table-hover">
                <tbody>
                <c:forEach items="${applications}" var="item">
                    <tr class="code clickable-row"
                        data-href="${pageContext.request.contextPath}/application/detail/<c:out value="${item.applicationId}"/>">
                        <td><c:out value="${item.applicationId}"/></td>
                    </tr>
                </c:forEach>
                </tbody>
            </table>
        </div>
    </c:otherwise>
</c:choose>

<jsp:include page="footer.jsp"/>