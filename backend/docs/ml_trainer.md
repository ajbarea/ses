# Machine Learning Pipeline Explanation

This document provides a high-level overview of the machine learning pipeline implemented in `ml_trainer.py`. The system is designed to predict a numerical security score and classify the security posture into a qualitative grade based on various system metrics.

## 1. Data Preprocessing (`SecurityDataset`)

The first step in the pipeline is to load and transform the raw data from a CSV file into a format suitable for training a neural network. This is handled by the `SecurityDataset` class.

- **Feature and Target Separation**: The dataset distinguishes between input features (e.g., `patch_status`, `ports_count`) and target variables (`target_score`, `target_grade`).

- **Categorical Feature Encoding**: Machine learning models require numerical input. Categorical features with text values (like `patch_status` which can be 'up-to-date' or 'out-of-date') are converted into integers using `sklearn.preprocessing.LabelEncoder`. Each unique category is assigned a unique number.

- **Numerical Feature Scaling**: Numerical features (like `ports_count`) often have different scales. To prevent features with larger ranges from dominating the learning process, their values are standardized using `sklearn.preprocessing.StandardScaler`. This process scales the features to have a mean of 0 and a standard deviation of 1.

- **Target Grade Encoding**: Similar to categorical features, the `target_grade` (e.g., "Excellent", "Critical Risk") is also converted into numerical labels using a dedicated `LabelEncoder` called `grade_encoder`. This is crucial for the classification task.

## 2. Model Architecture (`SecurityNN`)

The core of the pipeline is the `SecurityNN`, a multi-task PyTorch neural network. It is designed to perform two tasks simultaneously from the same set of input features.

- **Shared Base Layers**: The model can be conceptualized as having a common "body" that processes the input features.

- **Two Output Heads**:
  1. **Score Predictor (Regression Head)**: This head predicts the numerical `target_score`. It ends with a `Sigmoid` activation function, which squishes the output to a range between 0 and 1. This value is then scaled to produce the final score between 0 and 100.
  2. **Grade Classifier (Classification Head)**: This head predicts the `target_grade`. It outputs raw scores (logits) for each of the 5 possible grade categories.

This multi-task architecture allows the model to learn shared representations from the input data that are useful for both predicting the precise score and classifying the overall grade.

## 3. Training Process (`train_model`)

The `train_model` function orchestrates the training loop.

- **Loss Functions**:

  - For the score prediction, **Mean Squared Error (`nn.MSELoss`)** is used to measure the difference between the predicted and actual scores.
  - For the grade classification, **Cross-Entropy Loss (`nn.CrossEntropyLoss`)** is used, which is standard for multi-class classification tasks.

- **Combined Loss**: During training, the total loss is a weighted sum of the score loss and the grade loss (`total_loss = score_loss + 0.3 * grade_loss`). This encourages the model to learn both tasks, with a slightly higher emphasis on getting the score correct.

- **Optimization**: The `Adam` optimizer is used to update the model's weights based on the calculated loss, gradually improving its predictions over multiple epochs (passes through the training data).

## 4. Evaluation (`evaluate_security_model`)

After training, the model's performance is assessed on a separate test dataset using the `evaluate_security_model` function.

- **Standard Metrics**: It calculates standard regression metrics like Mean Squared Error (MSE), Mean Absolute Error (MAE), and R² to evaluate the accuracy of the score predictions.

- **Grade Accuracy**: It measures the percentage of grades the model classifies correctly.

- **Expert System Consistency**: This is a custom metric that measures the logical consistency between the model's two predictions. It checks if the predicted numerical score falls within the predefined score range for the predicted grade. For example, if the model predicts a grade of "Excellent", this metric checks if the predicted score is between 90 and 100. A high consistency score indicates that the model's two outputs are well-aligned.

## Alternative Model (`_train_sklearn_model`)

The pipeline also includes the capability to train a simple `sklearn.linear_model.LinearRegression` model. This serves as a quick baseline to compare against the more complex neural network, ensuring that the added complexity of the `SecurityNN` provides a tangible performance benefit.

This linear model was the legacy approach, developed as an initial proof-of-concept. While useful as a baseline, it is generally outperformed by the `SecurityNN` because:

- It can only model linear relationships between features and the security score.
- It does not utilize categorical features, which can contain valuable predictive information.
- It is a single-task model, only predicting the score without the accompanying grade classification.

The `SecurityNN` represents a more advanced and capable solution for this problem.
