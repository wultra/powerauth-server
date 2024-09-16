<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>

<jsp:include page="header.jsp">
    <jsp:param name="pageTitle" value="PowerAuth - Activations"/>
</jsp:include>


<c:choose>
    <c:when test="${userId == null}">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">User Selection</h3>
            </div>
            <div class="panel-body">
                <form action="${pageContext.request.contextPath}/activation/list" method="GET" class="form-inline">
                    Enter a user ID <input class="form-control" type="text" name="userId" value="<c:out value="${userId}"/>"/>
                    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
                    <input class="form-field btn btn-success" type="submit" value="Select User"/>
                </form>
            </div>
        </div>
    </c:when>
    <c:otherwise>

        <ol class="breadcrumb">
            <li><a class="black" href="${pageContext.request.contextPath}/activation/list">User Selection</a></li>
            <li class="active">User "<c:out value="${userId}"/>"</li>
        </ol>

        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">New Activation</h3>
            </div>
            <div class="panel-body">
                <c:if test="${not empty error}">
                    <div style="color: #c0007f; margin-bottom: 5px;"><c:out value="${error}"/></div>
                </c:if>
                <form action="${pageContext.request.contextPath}/activation/create?userId=<c:out value="${userId}"/>" class="form-inline pull-left">
                    <div class="form-group">
                        <select name="applicationId" class="form-control">
                            <c:forEach items="${applications}" var="item">
                                <option value="<c:out value="${item.applicationId}"/>">
                                    <c:out value="${item.applicationId}"/>
                                </option>
                            </c:forEach>
                        </select>
                        <select name="useOtp" class="form-control" onchange="if (this.selectedIndex > 0) document.getElementById('activationOtp').className='otp-displayed form-control'; else document.getElementById('activationOtp').className='otp-hidden';">
                            <option value="false">Do not use OTP</option>
                            <option value="true">Specify OTP</option>
                        </select>
                        <input type="text" size="12" name="activationOtp" id="activationOtp" class="otp-hidden"/>
                        <select name="commitPhase" class="form-control">
                            <option value="ON_COMMIT">Commit after key exchange</option>
                            <option value="ON_KEY_EXCHANGE">Commit during key exchange</option>
                        </select>
                        <input type="hidden" name="userId" value="<c:out value="${userId}"/>"/>
                        <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
                        <input type="submit" value="Create Activation" class="btn btn-default"/>
                    </div>
                </form>
            </div>
        </div>

        <c:if test="${not empty activations}">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h3 class="panel-title pull-left">Activations</h3>
                    <form action="${pageContext.request.contextPath}/activation/list" method="GET" class="pull-right">
                        <input type="hidden" name="userId" value="<c:out value="${userId}"/>"/>
                        <label style="font-weight: normal; margin: 0;">
                            <input type="checkbox" name="showAllActivations" <c:if test='${showAllActivations}'>checked</c:if> onchange="this.form.submit()"/> Show All
                        </label>
                        <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
                    </form>
                    <div class="clearfix"></div>
                </div>

                <table class="table table-hover">
                    <thead>
                    <tr>
                        <th style="width: 310px;">Activation ID</th>
                        <th>Name</th>
                        <th style="width: 80px;">Version</th>
                        <th style="width: 150px;">Application</th>
                        <th style="width: 80px;">Status</th>
                        <th style="width: 170px;">Last used</th>
                        <th class="text-right" style="width: 130px;">Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    <c:forEach items="${activations}" var="item">
                        <c:if test="${(showAllActivations == true) || (item.activationStatus == 'CREATED') || (item.activationStatus == 'ACTIVE') || (item.activationStatus == 'PENDING_COMMIT') || (item.activationStatus == 'BLOCKED')}">
                            <tr class="code clickable-row"
                                data-href='${pageContext.request.contextPath}/activation/detail/<c:out value="${item.activationId}"/>'>
                                <td><c:out value="${item.activationId}"/></td>
                                <td><c:out value="${item.activationName}"/></td>
                                <td>
                                    <c:choose>
                                        <c:when test="${item.version != 0}">
                                            <c:out value="${item.version}"/>
                                        </c:when>
                                        <c:otherwise>
                                            Unknown
                                        </c:otherwise>
                                    </c:choose>
                                </td>
                                <td>
                                    <a class="black"
                                       href='${pageContext.request.contextPath}/application/detail/<c:out value="${item.applicationId}"/>'><c:out
                                            value="${item.applicationId}"/></a>
                                </td>
                                <td>
                                    <jsp:include page="activationStatusSnippet.jsp">
                                        <jsp:param value="${item.activationStatus}" name="status"/>
                                    </jsp:include>
                                </td>
                                <td class="text-right">
                                    <fmt:formatDate type="both" pattern="yyyy/MM/dd HH:mm:ss" value="${item.timestampLastUsed}"/>
                                </td>
                                <td>
                                    <jsp:include page="activationStatusForms.jsp">
                                        <jsp:param value="${item.activationStatus}" name="status"/>
                                        <jsp:param value="${item.activationId}" name="activationId"/>
                                        <jsp:param value="${userId}" name="redirectUserId"/>
                                    </jsp:include>
                                </td>
                            </tr>
                        </c:if>
                    </c:forEach>
                    </tbody>
                </table>
            </div>
        </c:if>

        <c:if test="${not empty recoveryCodes}">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h3 class="panel-title pull-left">Recovery Codes</h3>
                    <form action="${pageContext.request.contextPath}/activation/list" method="GET" class="pull-right">
                        <input type="hidden" name="userId" value="<c:out value="${userId}"/>"/>
                        <label style="font-weight: normal; margin: 0;">
                            <input type="checkbox" name="showAllRecoveryCodes" <c:if test='${showAllRecoveryCodes}'>checked</c:if> onchange="this.form.submit()"/> Show All
                        </label>
                        <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
                    </form>
                    <div class="clearfix"></div>
                </div>

                <table class="table table-hover">
                    <thead>
                    <tr>
                        <th style="width: 310px;">Activation ID</th>
                        <th>Activation Code</th>
                        <th style="width: 80px;">Type</th>
                        <th style="width: 150px;">Application</th>
                        <th style="width: 80px;">Status</th>
                        <th style="width: 170px;">Current PUK Index</th>
                        <th class="text-right" style="width: 130px;">Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    <c:forEach items="${recoveryCodes}" var="item">
                        <c:if test="${(showAllRecoveryCodes == true) || (item.status == 'CREATED') || (item.status == 'ACTIVE') || (item.status == 'BLOCKED')}">
                            <c:choose>
                                <c:when test="${not empty item.activationId}">
                                    <tr class="code clickable-row" data-href='${pageContext.request.contextPath}/activation/detail/<c:out value="${item.activationId}"/>#versions'>
                                </c:when>
                                <c:otherwise>
                                    <tr class="code">
                                </c:otherwise>
                            </c:choose>
                                <td>
                                    <c:choose>
                                        <c:when test="${not empty item.activationId}">
                                            <c:out value="${item.activationId}"/></td>
                                        </c:when>
                                        <c:otherwise>
                                            *
                                        </c:otherwise>
                                    </c:choose>
                                <td><c:out value="${item.recoveryCodeMasked}"/></td>
                                <td>
                                    <c:choose>
                                        <c:when test="${not empty item.activationId}">
                                            Activation
                                        </c:when>
                                        <c:otherwise>
                                            Postcard
                                        </c:otherwise>
                                    </c:choose>
                                </td>
                                <td>
                                    <a class="black"
                                       href='${pageContext.request.contextPath}/application/detail/<c:out value="${item.applicationId}"/>#versions'>
                                        <c:forEach items="${applications}" var="application">
                                            <c:if test="${application.applicationId == item.applicationId}">
                                                <c:out value="${application.applicationId}"/>
                                            </c:if>
                                        </c:forEach>
                                    </a>
                                </td>
                                <td>
                                    <jsp:include page="recoveryCodeStatusSnippet.jsp">
                                        <jsp:param value="${item.status}" name="status"/>
                                    </jsp:include>
                                </td>
                            <td>
                                <c:set var="firstValidPuk" value="0"/>
                                <c:forEach items="${item.puks}" var="puk">
                                    <c:if test="${firstValidPuk == 0 and puk.status == 'VALID'}">
                                        <c:set var="firstValidPuk" value="${puk.pukIndex}"/>
                                    </c:if>
                                </c:forEach>
                                <c:choose>
                                    <c:when test="${firstValidPuk > 0}">
                                        <c:out value="${firstValidPuk}"/> of <c:out value="${item.puks.size()}"/>
                                    </c:when>
                                    <c:otherwise>
                                        Not Available
                                    </c:otherwise>
                                </c:choose>
                            </td>
                                <td>
                                    <c:if test="${item.status != 'REVOKED'}">
                                        <form action="${pageContext.request.contextPath}/activation/recovery/revoke/do.submit"
                                              method="POST" class="pull-right action-revoke">
                                            <input type="hidden" name="userId" value="<c:out value="${item.userId}"/>"/>
                                            <input type="hidden" name="recoveryCodeId"
                                                   value="<c:out value="${item.recoveryCodeId}"/>"/>
                                            <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
                                            <input type="submit" value="Revoke" class="btn btn-xs btn-danger"/>
                                        </form>
                                    </c:if>
                                </td>
                            </tr>
                        </c:if>
                    </c:forEach>
                    </tbody>
                </table>
            </div>
        </c:if>

    </c:otherwise>
</c:choose>


<jsp:include page="footer.jsp"/>