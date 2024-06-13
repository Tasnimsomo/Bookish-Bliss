#!/usr/bin/python3

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Table, Enum as SQLAlchemyEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
from enum import Enum
from flask_login import UserMixin

Base = declarative_base()

class Role(Enum):
    ADMIN = 'admin'
    CUSTOMER = 'customer'

class User(Base, UserMixin):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    role = Column(SQLAlchemyEnum(Role), nullable=False, server_default=Role.CUSTOMER.name)

    orders = relationship("Order", back_populates="user")
    reviews = relationship("Review", back_populates="user")
    cart = relationship("Cart", uselist=False, back_populates="user")
    addresses = relationship("Address", back_populates="user")
    

    def __repr__(self):
        return f"User(id={self.id}, username='{self.username}', email='{self.email}', role='{self.role.value}')"

class Author(Base):
    __tablename__ = 'authors'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    bio = Column(String)
    books = relationship("Book", back_populates="author")

class BookCategory(Base):
    __tablename__ = 'book_categories'
    id = Column(Integer, primary_key=True, index=True)
    book_id = Column(Integer, ForeignKey('books.id'), nullable=False)
    category_id = Column(Integer, ForeignKey('categories.id'), nullable=False)
    book = relationship("Book", back_populates="categories")
    category = relationship("Category", back_populates="books")

class Book(Base):
    __tablename__ = 'books'
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    author_id = Column(Integer, ForeignKey('authors.id'))
    price = Column(Float, nullable=False)
    quantity = Column(Integer, nullable=False)
    description = Column(String)
    author = relationship("Author", back_populates="books")
    reviews = relationship("Review", back_populates="book")
    order_items = relationship("OrderItem", back_populates="book")
    cart_items = relationship("CartItem", back_populates="book")
    categories = relationship("BookCategory", back_populates="book")

class Category(Base):
    __tablename__ = 'categories'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    books = relationship("BookCategory", back_populates="category")

class Order(Base):
    __tablename__ = 'orders'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="orders")
    items = relationship("OrderItem", back_populates="order")
    payments = relationship("Payment", back_populates="order")

class OrderItem(Base):
    __tablename__ = 'order_items'
    id = Column(Integer, primary_key=True, index=True)
    order_id = Column(Integer, ForeignKey('orders.id'), nullable=False)
    book_id = Column(Integer, ForeignKey('books.id'), nullable=False)
    quantity = Column(Integer, nullable=False)
    order = relationship("Order", back_populates="items")
    book = relationship("Book", back_populates="order_items")

class Payment(Base):
    __tablename__ = 'payments'
    id = Column(Integer, primary_key=True, index=True)
    order_id = Column(Integer, ForeignKey('orders.id'), nullable=False)
    amount = Column(Float, nullable=False)
    payment_date = Column(DateTime, default=datetime.utcnow)
    order = relationship("Order", back_populates="payments")

class Review(Base):
    __tablename__ = 'reviews'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    book_id = Column(Integer, ForeignKey('books.id'), nullable=False)
    rating = Column(Integer, nullable=False)
    comment = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="reviews")
    book = relationship("Book", back_populates="reviews")

class Cart(Base):
    __tablename__ = 'carts'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    user = relationship("User", back_populates="cart")
    items = relationship("CartItem", back_populates="cart")

class CartItem(Base):
    __tablename__ = 'cart_items'
    id = Column(Integer, primary_key=True, index=True)
    cart_id = Column(Integer, ForeignKey('carts.id'), nullable=False)
    book_id = Column(Integer, ForeignKey('books.id'), nullable=False)
    quantity = Column(Integer, nullable=False)
    cart = relationship("Cart", back_populates="items")
    book = relationship("Book", back_populates="cart_items")

class Address(Base):
    __tablename__ = 'addresses'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    street = Column(String, nullable=False)
    city = Column(String, nullable=False)
    state = Column(String, nullable=False)
    zip_code = Column(String, nullable=False)
    country = Column(String, nullable=False)
    user = relationship("User", back_populates="addresses")
