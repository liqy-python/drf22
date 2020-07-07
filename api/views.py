import re

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework_jwt.authentication import JSONWebTokenAuthentication,BaseJSONWebTokenAuthentication
from rest_framework_jwt.serializers import jwt_encode_handler, jwt_payload_handler,jwt_decode_handler
from rest_framework.filters import SearchFilter, OrderingFilter

from api.filter import LimitFilter, ComputerFilterSet
from api.pagination import MyPageNumberPagination,MyLimitPagination, MyCoursePagination
from utils.response import APIResponse
from api.models import User,Computer
from api.serializers import UserModelSerializer, ComputerModelSerializer
from api.authentication import JwTAuthentication


class UserDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JSONWebTokenAuthentication]
    # authentication_classes = [JwTAuthentication]

    def get(self, request, *args, **kwargs):
        return APIResponse(results={"username": request.user.username})


class LoginAPIView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request, *args, **kwargs):
        user_ser = UserModelSerializer(data=request.data)
        user_ser.is_valid(raise_exception=True)
        return APIResponse(data_message="ok", token=user_ser.token, results=UserModelSerializer)

    # 面向过程
    def demo_post(self, request, *args, **kwargs):
        account = request.data.get("account")
        pwd = request.data.get("pwd")
        if re.match(r'.+@.+', account):
            user_obj = User.objects.filter(email=account).first()
        elif re.match(r'1[3-9][0-9]{9}', account):
            user_obj = User.objects.filter(phone=account).first()
        else:
            user_obj = User.objects.filter(username=account).first()

        # 判断用户是否存在 且用户密码是否正确
        if user_obj and user_obj.check_password(pwd):
            # 生成载荷信息
            payload = jwt_payload_handler(user_obj)
            # 生成token
            token = jwt_encode_handler(payload)
            return APIResponse(results={"username": user_obj.username}, token=token)
        return APIResponse(data_message="错误了")


# 游标分页
class ComputerListAPIView(ListAPIView):
    queryset = Computer.objects.all()
    serializer_class = ComputerModelSerializer

    filter_backends = [SearchFilter,OrderingFilter, LimitFilter, DjangoFilterBackend]
    # 指定当前搜索条件
    search_fields = ["name","price"]
    # 指定排序的条件
    ordering = ["price"]
    # 指定分页器     不能使用列表 或 元组
    pagination_class = MyPageNumberPagination
    # pagination_class = MyLimitPagination
    # pagination_class = MyCoursePagination

    # django-filter 查询   通过filter_class指定过滤器
    filter_class = ComputerFilterSet