# SecureTrainer - Cybersecurity Awareness Training Platform

## 🎯 Project Overview

**SecureTrainer** is a comprehensive web-based cybersecurity training application designed as a final year project for a Bachelor's degree in Cyber Security. The platform provides interactive, gamified learning experiences to help employees develop cybersecurity awareness and skills.

## 🚀 Key Features

### 🔐 Secure Authentication
- **QR Code-Based Login**: Unique QR codes sent via email for secure authentication
- **No Traditional Passwords**: Eliminates password-related security risks
- **Session Management**: Secure session handling with automatic expiration

### 🎮 Gamified Learning
- **Multiple Challenge Categories**:
  - SQL Injection vulnerabilities
  - Cross-Site Scripting (XSS)
  - Command Injection attacks
  - Authentication vulnerabilities
  - CSRF (Cross-Site Request Forgery)
- **Progressive Difficulty**: Challenges adapt to user skill level
- **Scoring System**: Points-based progression with role promotions
- **Achievement Tracking**: Monitor progress and celebrate milestones

### 🤖 AI-Powered Learning
- **Adaptive Difficulty**: AI model adjusts challenge complexity based on performance
- **Personalized Recommendations**: Tailored challenge suggestions
- **Learning Pattern Analysis**: Insights into strengths and areas for improvement
- **Performance Prediction**: AI estimates success probability for challenges

### 📊 Comprehensive Analytics
- **Progress Tracking**: Monitor advancement across all challenge categories
- **Performance Metrics**: Success rates, completion times, and learning patterns
- **Leaderboards**: Compare performance with colleagues
- **Department Rankings**: Track progress within organizational units

### 🏢 Enterprise Features
- **Department Management**: Organize users by company departments
- **Role-Based Promotions**: Automatic role advancement based on performance
- **Company Integration**: Seamless integration with organizational structures
- **Scalable Architecture**: Designed for enterprise deployment

## 🛠️ Technology Stack

### Backend
- **Flask**: Python web framework
- **MongoDB**: NoSQL database for user data and analytics
- **Flask-Mail**: Email functionality for QR code delivery
- **bcrypt**: Secure password hashing
- **qrcode**: QR code generation and management

### Frontend
- **HTML5/CSS3**: Modern, responsive design
- **Tailwind CSS**: Utility-first CSS framework
- **JavaScript**: Interactive functionality and API integration
- **Chart.js**: Data visualization and analytics

### AI/ML
- **scikit-learn**: Machine learning models for difficulty prediction
- **pandas/numpy**: Data processing and analysis
- **joblib**: Model persistence and loading

### Security
- **Environment Variables**: Secure configuration management
- **Input Validation**: Comprehensive security measures
- **Session Security**: Secure session handling
- **CORS Protection**: Cross-origin resource sharing security

## 📋 Prerequisites

Before running SecureTrainer, ensure you have:

- **Python 3.8+** installed
- **MongoDB** running locally or accessible remotely
- **Email Service** credentials (Gmail, Outlook, etc.)
- **Git** for version control

## 🚀 Installation & Setup

### 1. Clone the Repository
```bash
git clone <repository-url>
cd securetrainer
```

### 2. Create Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Environment Configuration
Create a `.env` file in the project root:

```env
# Security
SECRET_KEY=your-super-secret-key-here

# Email Configuration
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password

# Database
MONGO_URI=mongodb://localhost:27017/securetrainer

# Optional: Development Settings
FLASK_ENV=development
DEBUG=True
```

### 5. Database Setup
Ensure MongoDB is running and accessible. The application will automatically create necessary collections.

### 6. Run the Application
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## 📱 Usage Guide

### For Employees

#### 1. Registration
- Visit the registration page
- Fill in personal and company information
- Receive QR code via email

#### 2. Login
- Use the QR code scanner on the login page
- Upload QR code image if webcam unavailable
- Access your personalized dashboard

#### 3. Training
- Choose challenge categories based on interests
- Complete challenges to earn points
- Use hints when needed
- Track progress and achievements

#### 4. Progress Monitoring
- View performance analytics
- Check rankings and achievements
- Monitor skill development

### For Administrators

#### 1. User Management
- Monitor user registrations
- Track department performance
- Manage user roles and permissions

#### 2. Analytics Dashboard
- View overall platform statistics
- Analyze learning patterns
- Generate performance reports

#### 3. Challenge Management
- Review challenge effectiveness
- Adjust difficulty levels
- Monitor completion rates

## 🔧 Configuration Options

### Challenge Difficulty
- **Beginner**: Basic concepts and simple scenarios
- **Intermediate**: Moderate complexity with real-world examples
- **Advanced**: Complex scenarios requiring deep understanding
- **Expert**: Advanced techniques and sophisticated attacks

### Scoring System
- **Base Points**: 100 points per completed challenge
- **Difficulty Multipliers**: Higher difficulty = more points
- **Bonus Points**: Speed bonuses, hint efficiency, etc.
- **Role Promotions**: Automatic advancement based on score thresholds

### Email Templates
- **Welcome Emails**: Personalized with QR codes
- **Challenge Completion**: Achievement notifications
- **Role Promotions**: Career advancement announcements

## 🧪 Testing

### Manual Testing
1. **Registration Flow**: Test user registration and email delivery
2. **QR Code Generation**: Verify QR code creation and validation
3. **Challenge System**: Test all challenge types and difficulty levels
4. **AI Recommendations**: Verify adaptive difficulty adjustment
5. **Email Functionality**: Test all email templates and delivery

### Automated Testing
```bash
# Run test suite
python -m pytest tests/

# Run with coverage
python -m pytest --cov=app tests/
```

## 📊 Performance Metrics

### User Engagement
- **Daily Active Users**: Track platform usage
- **Challenge Completion Rates**: Monitor learning effectiveness
- **Time Spent**: Measure engagement duration
- **Return Visits**: Track user retention

### Learning Effectiveness
- **Success Rates**: Challenge completion success
- **Skill Progression**: Level advancement rates
- **Knowledge Retention**: Long-term learning outcomes
- **Department Performance**: Organizational impact

### Technical Performance
- **Response Times**: API and page load performance
- **Database Performance**: Query optimization
- **Email Delivery**: Success rates and delivery times
- **System Uptime**: Platform reliability

## 🔒 Security Features

### Authentication & Authorization
- **QR Code Security**: Time-limited, unique authentication tokens
- **Session Management**: Secure session handling with expiration
- **Input Validation**: Comprehensive security against injection attacks
- **CSRF Protection**: Cross-site request forgery prevention

### Data Protection
- **Password Hashing**: bcrypt with salt for secure storage
- **Environment Variables**: Secure configuration management
- **Database Security**: MongoDB security best practices
- **HTTPS Enforcement**: Secure communication protocols

### Application Security
- **Input Sanitization**: Prevent XSS and injection attacks
- **Error Handling**: Secure error messages without information leakage
- **Rate Limiting**: Prevent abuse and brute force attacks
- **Logging & Monitoring**: Security event tracking

## 🚀 Deployment

### Production Deployment
1. **Server Setup**: Configure production server with HTTPS
2. **Database**: Set up production MongoDB instance
3. **Email Service**: Configure production email credentials
4. **Environment Variables**: Set production configuration
5. **Process Management**: Use Gunicorn or uWSGI
6. **Reverse Proxy**: Configure Nginx for load balancing

### Docker Deployment
```bash
# Build Docker image
docker build -t securetrainer .

# Run container
docker run -p 5000:5000 --env-file .env securetrainer
```

### Cloud Deployment
- **AWS**: EC2 with RDS and SES
- **Azure**: App Service with Cosmos DB
- **Google Cloud**: App Engine with Firestore
- **Heroku**: Platform-as-a-Service deployment

## 📈 Future Enhancements

### Planned Features
- **Mobile Application**: Native iOS and Android apps
- **Advanced AI**: Machine learning for personalized learning paths
- **Virtual Labs**: Interactive cybersecurity lab environments
- **Certification System**: Industry-recognized cybersecurity certifications
- **Team Challenges**: Collaborative learning experiences
- **Real-time Collaboration**: Live training sessions and competitions

### Technical Improvements
- **Microservices Architecture**: Scalable service-based design
- **Real-time Updates**: WebSocket integration for live features
- **Advanced Analytics**: Business intelligence and reporting
- **API Documentation**: Comprehensive API documentation
- **Performance Optimization**: Caching and optimization strategies

## 🤝 Contributing

### Development Guidelines
1. **Code Style**: Follow PEP 8 Python style guide
2. **Documentation**: Maintain comprehensive docstrings
3. **Testing**: Write tests for new features
4. **Security**: Follow security best practices
5. **Performance**: Optimize for speed and efficiency

### Contribution Process
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests and documentation
5. Submit a pull request

## 📄 License

This project is developed as a final year project for educational purposes. All rights reserved.

## 👥 Team

- **Developer**: [Your Name]
- **Supervisor**: [Supervisor Name]
- **Institution**: [Your University]
- **Degree**: Bachelor's in Cyber Security

## 📞 Support

For support and questions:
- **Email**: [your-email@university.edu]
- **Project Repository**: [GitHub URL]
- **Documentation**: [Documentation URL]

## 🙏 Acknowledgments

- **University Faculty**: For guidance and supervision
- **Open Source Community**: For the excellent tools and libraries
- **Cybersecurity Community**: For inspiration and best practices
- **Peers**: For feedback and testing support

---

**SecureTrainer** - Empowering organizations through cybersecurity education and awareness training.
